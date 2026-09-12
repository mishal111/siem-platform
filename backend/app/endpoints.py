import secrets
from datetime import UTC, datetime
from uuid import UUID

from fastapi import HTTPException
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError
from pymongo.write_concern import WriteConcern

from app.identity import Principal, token_hash
from app.models import OperatingSystem, ShortText


class EndpointCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    endpoint_id: UUID
    hostname: ShortText
    os: OperatingSystem


class EndpointRecord(BaseModel):
    endpoint_id: str
    hostname: str
    os: OperatingSystem
    active: bool
    revision: int
    key_suffix: str
    created_at: AwareDatetime


class EndpointCredential(BaseModel):
    endpoint: EndpointRecord
    api_key: str


class EndpointPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_revision: int = Field(ge=0)
    active: bool


class KeyRotation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_revision: int = Field(ge=0)


class Heartbeat(BaseModel):
    model_config = ConfigDict(extra="forbid")
    endpoint_id: UUID
    hostname: ShortText
    os: OperatingSystem
    collector_version: ShortText
    pending: int = Field(ge=0, le=100000)
    rejected: int = Field(ge=0, le=100000)
    source_error: ShortText | None = None


def public_endpoint(row):
    return EndpointRecord(endpoint_id=row["_id"], **row)


class EndpointStore:
    def __init__(self, database):
        concern = WriteConcern(w="majority", j=True, wtimeout=5000)
        self.collection = database.get_collection("endpoints", write_concern=concern)
        self.hosts = database.get_collection("hosts", write_concern=concern)

    def initialize(self):
        self.collection.create_index("key_hash", unique=True)
        self.hosts.create_index("last_seen_at")

    def create(self, data: EndpointCreate, actor):
        token = "siem_agent_" + secrets.token_urlsafe(32)
        now = datetime.now(UTC)
        row = {
            "_id": str(data.endpoint_id),
            "hostname": data.hostname,
            "os": data.os.value,
            "active": True,
            "revision": 0,
            "created_at": now,
            "key_hash": token_hash(token),
            "key_suffix": token[-6:],
            "history": [{"actor_id": actor, "at": now, "action": "enrolled"}],
        }
        try:
            self.collection.insert_one(row)
        except DuplicateKeyError:
            raise HTTPException(
                409, "Endpoint already enrolled; rotate its key if needed"
            ) from None
        return EndpointCredential(endpoint=public_endpoint(row), api_key=token)

    def authenticate(self, key):
        row = self.collection.find_one({"key_hash": token_hash(key), "active": True})
        if not row:
            raise HTTPException(401, "Invalid or revoked collector key")
        return Principal(endpoint_id=row["_id"])

    def check_scope(self, principal, endpoint_id, os):
        if principal.legacy:
            return
        row = self.collection.find_one({"_id": principal.endpoint_id, "active": True})
        if str(endpoint_id) != principal.endpoint_id or not row or row["os"] != os:
            raise HTTPException(403, "Collector credential does not authorize this endpoint and OS")

    def update(self, endpoint_id, revision, actor, active=None, rotate=False):
        token = "siem_agent_" + secrets.token_urlsafe(32) if rotate else None
        values = (
            {"key_hash": token_hash(token), "key_suffix": token[-6:]}
            if token
            else {"active": active}
        )
        result = self.collection.find_one_and_update(
            {"_id": endpoint_id, "revision": revision, "history.499": {"$exists": False}},
            {
                "$set": values,
                "$inc": {"revision": 1},
                "$push": {
                    "history": {
                        "actor_id": actor,
                        "at": datetime.now(UTC),
                        "action": "key_rotated" if rotate else "enabled" if active else "revoked",
                    }
                },
            },
            return_document=ReturnDocument.AFTER,
        )
        if not result:
            if not self.collection.find_one({"_id": endpoint_id}, {"_id": 1}):
                raise HTTPException(404, "Endpoint not found")
            raise HTTPException(409, "Endpoint changed or history is full; reload before editing")
        return (
            EndpointCredential(endpoint=public_endpoint(result), api_key=token)
            if token
            else public_endpoint(result)
        )

    def observe(
        self,
        endpoint_id,
        hostname,
        os,
        event_received=None,
        heartbeat=None,
        observed_at=None,
        first_observed_at=None,
    ):
        now = observed_at or datetime.now(UTC)
        stamp = event_received or now
        epoch = datetime(1970, 1, 1, tzinfo=UTC)
        first = first_observed_at or now
        current = {"$gte": [stamp, {"$ifNull": ["$metadata_at", epoch]}]}
        values = {
            "hostname": {"$cond": [current, {"$literal": hostname}, "$hostname"]},
            "os": {"$cond": [current, {"$literal": os}, "$os"]},
            "metadata_at": {"$max": ["$metadata_at", stamp]},
            "first_seen_at": {"$min": [{"$ifNull": ["$first_seen_at", first]}, first]},
            "last_seen_at": {"$max": ["$last_seen_at", now]},
        }
        if event_received:
            values["last_event_received_at"] = {"$max": ["$last_event_received_at", event_received]}
        if heartbeat:
            details = {
                "last_heartbeat_at": now,
                "collector_version": heartbeat.collector_version,
                "pending": heartbeat.pending,
                "rejected": heartbeat.rejected,
                "source_error": heartbeat.source_error,
            }
            for key, value in details.items():
                values[key] = {"$cond": [current, {"$literal": value}, "$" + key]}
        self.hosts.update_one({"_id": str(endpoint_id)}, [{"$set": values}], upsert=True)
