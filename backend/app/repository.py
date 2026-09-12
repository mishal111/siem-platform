import base64
import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from bson import ObjectId
from pydantic import AwareDatetime, BaseModel, ConfigDict, ValidationError, field_validator
from pymongo import ASCENDING, DESCENDING, MongoClient
from pymongo.errors import DuplicateKeyError
from pymongo.write_concern import WriteConcern

from app.alerts import AlertEvidence, AlertFilters, AlertPage, AlertRecord, AlertStore
from app.config import Settings
from app.endpoints import EndpointStore
from app.identity import IdentityStore
from app.models import EventFilters, EventInput, EventPage, EventRecord


class EventConflict(Exception):
    """An endpoint reused an event UID for a different payload."""


class InvalidCursor(Exception):
    """A pagination cursor is malformed."""


class Cursor(BaseModel):
    model_config = ConfigDict(extra="forbid")
    timestamp: AwareDatetime
    id: str

    @field_validator("id")
    @classmethod
    def valid_id(cls, value: str) -> str:
        if not ObjectId.is_valid(value):
            raise ValueError("Invalid event ID")
        return value


def encode_cursor(event: EventRecord) -> str:
    payload = Cursor(timestamp=event.timestamp, id=event.id).model_dump_json()
    return base64.urlsafe_b64encode(payload.encode()).decode()


def decode_cursor(value: str) -> Cursor:
    try:
        decoded = base64.b64decode(value, altchars=b"-_", validate=True)
        return Cursor.model_validate_json(decoded)
    except (ValueError, ValidationError) as exc:
        raise InvalidCursor from exc


def build_query(filters: EventFilters) -> dict[str, Any]:
    query = filters.model_dump(
        mode="json", exclude_none=True, exclude={"start_time", "end_time", "limit", "cursor"}
    )
    if filters.start_time or filters.end_time:
        query["timestamp"] = {}
        if filters.start_time:
            query["timestamp"]["$gte"] = filters.start_time
        if filters.end_time:
            query["timestamp"]["$lte"] = filters.end_time
    if filters.cursor:
        cursor = decode_cursor(filters.cursor)
        query["$or"] = [
            {"timestamp": {"$lt": cursor.timestamp}},
            {"timestamp": cursor.timestamp, "_id": {"$lt": ObjectId(cursor.id)}},
        ]
    return query


def to_record(document: dict[str, Any]) -> EventRecord:
    public = {name: document[name] for name in EventInput.model_fields if name in document}
    return EventRecord(**public, id=str(document["_id"]), received_at=document["received_at"])


class EventRepository:
    def __init__(self, settings: Settings):
        self.client = MongoClient(
            settings.mongo_uri.get_secret_value(),
            tz_aware=True,
            serverSelectionTimeoutMS=3000,
            connectTimeoutMS=3000,
            socketTimeoutMS=5000,
            timeoutMS=8000,
            appname="siem-backend",
        )
        self.collection = self.client[settings.mongo_db].get_collection(
            "events", write_concern=WriteConcern(w="majority", j=True, wtimeout=5000)
        )
        self.alerts = AlertStore(self.collection.database)
        self.identity = IdentityStore(self.collection.database, settings)
        self.endpoints = EndpointStore(self.collection.database)

    def initialize(self) -> None:
        self.ping()
        self.collection.create_index(
            [("endpoint_id", ASCENDING), ("event_uid", ASCENDING)],
            unique=True,
            name="endpoint_event_uid_unique",
        )
        for prefix in ([], [("hostname", ASCENDING)], [("event_type", ASCENDING)]):
            self.collection.create_index(prefix + [("timestamp", DESCENDING), ("_id", DESCENDING)])
        self.collection.create_index([("processing_status", 1), ("received_at", 1)])
        self.collection.create_index(
            [
                ("endpoint_id", 1),
                ("username", 1),
                ("source_ip", 1),
                ("event_type", 1),
                ("timestamp", 1),
                ("_id", 1),
            ]
        )
        self.alerts.initialize()
        self.identity.initialize()
        self.endpoints.initialize()
        self.collection.create_index([("received_at", 1), ("_id", 1)])
        self.collection.create_index([("endpoint_id", 1), ("received_at", -1)])

    def ping(self) -> None:
        self.client.admin.command("ping")

    def observe_endpoint(self, event, received_at):
        self.endpoints.observe(
            event.endpoint_id, event.hostname, event.os.value, event_received=received_at
        )

    def close(self) -> None:
        self.client.close()

    def insert(self, event: EventInput) -> tuple[EventRecord, bool]:
        payload = event.model_dump(mode="json")
        digest = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        ).hexdigest()
        now = datetime.now(UTC)
        document = {
            **payload,
            "timestamp": event.timestamp,
            "received_at": now.replace(microsecond=(now.microsecond // 1000) * 1000),
            "payload_hash": digest,
            "processing_status": "pending",
        }
        try:
            self.collection.insert_one(document)
        except DuplicateKeyError:
            existing = self.collection.find_one(
                {"endpoint_id": event.endpoint_id, "event_uid": str(event.event_uid)}
            )
            if existing is None or existing["payload_hash"] != digest:
                raise EventConflict from None
            return to_record(existing), True
        return to_record(document), False

    def get(self, record_id: str) -> EventRecord | None:
        document = self.collection.find_one({"_id": ObjectId(record_id)})
        return to_record(document) if document is not None else None

    def search(self, filters: EventFilters) -> EventPage:
        cursor = (
            self.collection.find(build_query(filters))
            .sort([("timestamp", DESCENDING), ("_id", DESCENDING)])
            .limit(filters.limit + 1)
            .max_time_ms(3000)
        )
        records = [to_record(document) for document in cursor]
        has_more = len(records) > filters.limit
        items = records[: filters.limit]
        return EventPage(items=items, next_cursor=encode_cursor(items[-1]) if has_more else None)

    def search_alerts(self, filters: AlertFilters) -> AlertPage:
        return self.alerts.search(filters)

    def get_alert(self, record_id: str) -> AlertRecord | None:
        return self.alerts.get(record_id)

    def alert_evidence(self, record_id: str) -> AlertEvidence | None:
        alert = self.get_alert(record_id)
        if alert is None:
            return None
        documents = self.collection.find(
            {"_id": {"$in": [ObjectId(value) for value in alert.related_event_ids]}}
        ).sort([("timestamp", 1), ("_id", 1)])
        items = [to_record(document) for document in documents]
        found = {event.id for event in items}
        return AlertEvidence(
            items=items,
            missing_event_ids=[value for value in alert.related_event_ids if value not in found],
        )

    def detection_status(self) -> dict:
        counts = {
            row["_id"]: row["count"]
            for row in self.collection.aggregate(
                [{"$group": {"_id": "$processing_status", "count": {"$sum": 1}}}], maxTimeMS=3000
            )
        }
        state = self.collection.database.detection_state.find_one({"_id": "worker"}) or {}
        last_seen = state.get("last_seen_at")
        return {
            "events": {
                key: counts.get(key, 0)
                for key in ("pending", "processing", "processed", "skipped", "failed")
            },
            "worker_last_seen_at": last_seen,
            "worker_recent": bool(
                last_seen and (datetime.now(UTC) - last_seen).total_seconds() < 90
            ),
            "worker_last_error": state.get("last_error_type"),
        }
