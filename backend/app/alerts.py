import hashlib
import json
from datetime import UTC, datetime
from typing import Literal
from uuid import UUID, uuid4

from bson import ObjectId
from fastapi import HTTPException
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator
from pymongo import ASCENDING, DESCENDING, ReturnDocument
from pymongo.errors import DuplicateKeyError
from pymongo.write_concern import WriteConcern

from app.models import EventRecord, OperatingSystem, Severity, ShortText

AlertStatus = Literal["open", "investigating", "resolved", "false_positive"]


class AlertRecord(BaseModel):
    id: str
    rule_id: str
    rule_version: int
    rule_name: str
    severity: Severity
    status: AlertStatus = "open"
    revision: int = 0
    assigned_to: str | None = None
    updated_at: AwareDatetime | None = None
    note_count: int = 0
    endpoint_id: str
    hostname: str
    os: OperatingSystem
    username: str | None = None
    user_domain: str | None = None
    source_ip: str | None = None
    description: str
    mitre_technique: str
    mitre_name: str
    event_count: int
    failure_count: int
    first_seen: AwareDatetime
    last_seen: AwareDatetime
    created_at: AwareDatetime
    trigger_event_id: str
    related_event_ids: list[str]


class AlertPage(BaseModel):
    items: list[AlertRecord]
    next_cursor: str | None


class AlertEvidence(BaseModel):
    items: list[EventRecord]
    missing_event_ids: list[str]


class AlertFilters(BaseModel):
    model_config = ConfigDict(extra="forbid")

    endpoint_id: ShortText | None = None
    hostname: ShortText | None = None
    rule_id: ShortText | None = None
    severity: Severity | None = None
    status: AlertStatus | None = None
    assigned_to: ShortText | None = None
    mitre_technique: ShortText | None = None
    start_time: AwareDatetime | None = None
    end_time: AwareDatetime | None = None
    limit: int = Field(default=50, ge=1, le=200)
    cursor: str | None = Field(default=None, max_length=512)

    @model_validator(mode="after")
    def ordered_window(self) -> "AlertFilters":
        if self.start_time and self.end_time and self.start_time > self.end_time:
            raise ValueError("start_time must not be after end_time")
        return self


def to_alert(document: dict) -> AlertRecord:
    return AlertRecord(id=str(document["_id"]), **document)


class AlertUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_revision: int = Field(ge=0)
    status: AlertStatus | None = None
    assigned_to: UUID | None = None


class NoteCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    note_id: UUID
    expected_revision: int = Field(ge=0)
    text: str = Field(min_length=1, max_length=4000)


class AlertNote(BaseModel):
    id: str
    actor_id: str
    text: str
    created_at: AwareDatetime


class AlertHistoryEntry(BaseModel):
    id: str
    revision: int
    actor_id: str
    action: str
    at: AwareDatetime
    changes: dict


class AlertStore:
    def __init__(self, database):
        self.collection = database.get_collection(
            "alerts", write_concern=WriteConcern(w="majority", j=True, wtimeout=5000)
        )

    def initialize(self) -> None:
        self.collection.create_index("dedup_key", unique=True)
        self.collection.create_index([("created_at", DESCENDING), ("_id", DESCENDING)])
        self.collection.create_index(
            [("endpoint_id", ASCENDING), ("created_at", DESCENDING), ("_id", DESCENDING)]
        )
        self.collection.create_index([("status", 1), ("created_at", -1), ("_id", -1)])
        self.collection.create_index([("assigned_to", 1), ("created_at", -1), ("_id", -1)])
        self.collection.create_index("related_event_ids")

    def insert_once(self, identity: list, payload: dict) -> None:
        key = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
        now = datetime.now(UTC)
        document = {
            **payload,
            "dedup_key": key,
            "status": "open",
            "revision": 0,
            "assigned_to": None,
            "note_count": 0,
            "created_at": now.replace(microsecond=(now.microsecond // 1000) * 1000),
        }
        try:
            self.collection.update_one({"dedup_key": key}, {"$setOnInsert": document}, upsert=True)
        except DuplicateKeyError:
            # A concurrent evaluation inserted this same immutable alert first.
            if self.collection.find_one({"dedup_key": key}, {"_id": 1}) is None:
                raise

    def get(self, record_id: str) -> AlertRecord | None:
        document = self.collection.find_one(
            {"_id": ObjectId(record_id)}, {"notes": 0, "history": 0}
        )
        return to_alert(document) if document else None

    def search(self, filters: AlertFilters) -> AlertPage:
        import base64

        from app.repository import Cursor, decode_cursor

        query = filters.model_dump(
            mode="json", exclude_none=True, exclude={"start_time", "end_time", "limit", "cursor"}
        )
        if filters.start_time or filters.end_time:
            query["created_at"] = {}
            if filters.start_time:
                query["created_at"]["$gte"] = filters.start_time
            if filters.end_time:
                query["created_at"]["$lte"] = filters.end_time
        if filters.cursor:
            cursor = decode_cursor(filters.cursor)
            query["$or"] = [
                {"created_at": {"$lt": cursor.timestamp}},
                {"created_at": cursor.timestamp, "_id": {"$lt": ObjectId(cursor.id)}},
            ]
        documents = list(
            self.collection.find(query, {"notes": 0, "history": 0})
            .sort([("created_at", -1), ("_id", -1)])
            .limit(filters.limit + 1)
            .max_time_ms(3000)
        )
        items = [to_alert(document) for document in documents[: filters.limit]]
        cursor = None
        if len(documents) > filters.limit:
            payload = Cursor(timestamp=items[-1].created_at, id=items[-1].id).model_dump_json()
            cursor = base64.urlsafe_b64encode(payload.encode()).decode()
        return AlertPage(items=items, next_cursor=cursor)

    def workflow_document(self, record_id):
        row = self.collection.find_one({"_id": ObjectId(record_id)})
        if not row:
            raise HTTPException(404, "Alert not found")
        return row

    def mutate(self, record_id, revision, actor, changes, action, note=None):
        now = datetime.now(UTC)
        selector = {"_id": ObjectId(record_id), "history.499": {"$exists": False}}
        selector["$or"] = [{"revision": revision}] + (
            [{"revision": {"$exists": False}}] if revision == 0 else []
        )
        history = {
            "id": str(uuid4()),
            "actor_id": actor,
            "revision": revision + 1,
            "action": action,
            "at": now,
            "changes": changes,
        }
        update = {
            "$set": {**changes, "updated_at": now},
            "$inc": {"revision": 1},
            "$push": {"history": history},
        }
        if note:
            selector["notes.99"] = {"$exists": False}
            selector["notes.id"] = {"$ne": note["id"]}
            update["$push"]["notes"] = note
            update["$inc"]["note_count"] = 1
            history["changes"] = {"note_id": note["id"]}
        result = self.collection.find_one_and_update(
            selector, update, return_document=ReturnDocument.AFTER
        )
        if not result:
            self.workflow_document(record_id)
            raise HTTPException(
                409, "Alert changed or its history/note limit was reached; reload before editing"
            )
        return to_alert(result)

    def update(self, record_id, data: AlertUpdate, actor):
        changes = {}
        if "status" in data.model_fields_set:
            if data.status is None:
                raise HTTPException(422, "Status cannot be null")
            changes["status"] = data.status
        if "assigned_to" in data.model_fields_set:
            changes["assigned_to"] = str(data.assigned_to) if data.assigned_to else None
        if not changes:
            raise HTTPException(422, "Provide a status or assignment change")
        return self.mutate(record_id, data.expected_revision, actor, changes, "updated")

    def add_note(self, record_id, data: NoteCreate, actor):
        row = self.workflow_document(record_id)
        if not data.text.strip():
            raise HTTPException(422, "Note text cannot be blank")
        for existing in row.get("notes", []):
            if existing["id"] == str(data.note_id):
                if existing["actor_id"] != actor or existing["text"] != data.text:
                    raise HTTPException(409, "Note ID already exists with different content")
                return AlertNote(**existing)
        note = {
            "id": str(data.note_id),
            "actor_id": actor,
            "text": data.text,
            "created_at": datetime.now(UTC),
        }
        self.mutate(record_id, data.expected_revision, actor, {}, "note_added", note)
        return AlertNote(**note)
