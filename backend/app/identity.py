import hashlib
import secrets
import threading
from datetime import UTC, datetime, timedelta
from typing import Literal
from uuid import uuid4

from fastapi import HTTPException
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, SecretStr, field_validator
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError
from pymongo.write_concern import WriteConcern

Role = Literal["viewer", "analyst", "admin"]
Password = SecretStr
HASH_SLOTS = threading.BoundedSemaphore(2)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def password_digest(password: str, salt: str) -> str:
    if not HASH_SLOTS.acquire(blocking=False):
        raise HTTPException(
            429, "Authentication capacity reached; retry shortly", headers={"Retry-After": "2"}
        )
    try:
        return hashlib.scrypt(
            password.encode(),
            salt=bytes.fromhex(salt),
            n=2**17,
            r=8,
            p=1,
            maxmem=256 * 1024 * 1024,
            dklen=32,
        ).hex()
    finally:
        HASH_SLOTS.release()


def hash_password(password: str) -> dict:
    salt = secrets.token_hex(16)
    return {
        "algorithm": "scrypt-131072-8-1",
        "salt": salt,
        "digest": password_digest(password, salt),
    }


def check_password(password: str, saved: dict | None) -> bool:
    saved = saved or {"salt": "00" * 16, "digest": "00" * 32}
    return secrets.compare_digest(password_digest(password, saved["salt"]), saved["digest"])


class Credentials(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    username: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{2,63}$")
    password: Password = Field(min_length=12, max_length=128)

    @field_validator("username")
    @classmethod
    def canonical_username(cls, value):
        return value.lower()


class UserCreate(Credentials):
    role: Role = "analyst"


class UserRecord(BaseModel):
    id: str
    username: str
    role: Role
    active: bool
    revision: int
    created_at: AwareDatetime


class UserPatch(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    expected_revision: int = Field(ge=0)
    role: Role | None = None
    active: bool | None = None
    password: Password | None = Field(default=None, min_length=12, max_length=128)


class PasswordChange(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    current_password: Password = Field(min_length=12, max_length=128)
    new_password: Password = Field(min_length=12, max_length=128)


class SessionResult(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_at: AwareDatetime
    user: UserRecord


class Principal(BaseModel):
    user_id: str | None = None
    username: str | None = None
    role: Role = "viewer"
    session_hash: str | None = Field(default=None, exclude=True)
    endpoint_id: str | None = None
    legacy: bool = False


def public_user(row):
    return UserRecord(id=row["_id"], **row)


class IdentityStore:
    def __init__(self, database, settings):
        self.settings = settings
        concern = WriteConcern(w="majority", j=True, wtimeout=5000)
        self.users = database.get_collection("users", write_concern=concern)
        self.sessions = database.get_collection("sessions", write_concern=concern)
        self.throttles = database.get_collection("login_throttles", write_concern=concern)

    def initialize(self):
        self.users.create_index("username", unique=True)
        self.sessions.create_index("expires_at", expireAfterSeconds=0)
        self.sessions.create_index("user_id")
        self.throttles.create_index("expires_at", expireAfterSeconds=0)

    def create_user(self, data: UserCreate, actor: str):
        now = datetime.now(UTC)
        row = {
            "_id": str(uuid4()),
            "username": data.username,
            "role": data.role,
            "active": True,
            "revision": 0,
            "auth_version": 0,
            "created_at": now,
            "password_hash": hash_password(data.password.get_secret_value()),
            "history": [{"actor_id": actor, "at": now, "action": "created", "role": data.role}],
        }
        try:
            self.users.insert_one(row)
        except DuplicateKeyError:
            raise HTTPException(409, "Username already exists") from None
        return public_user(row)

    def throttle(self, username, peer):
        now = datetime.now(UTC)
        bucket = int(now.timestamp()) // 60
        for kind, value, maximum in (
            ("peer", peer, self.settings.login_peer_attempts),
            ("user", username, self.settings.login_user_attempts),
        ):
            key = f"{kind}:{token_hash(value)}:{bucket}"
            result = self.throttles.find_one_and_update(
                {"_id": key},
                {"$inc": {"count": 1}, "$setOnInsert": {"expires_at": now + timedelta(minutes=5)}},
                upsert=True,
                return_document=ReturnDocument.AFTER,
            )
            if result["count"] > maximum:
                raise HTTPException(
                    429,
                    "Too many login attempts; retry later",
                    headers={"Retry-After": str(60 - int(now.timestamp()) % 60)},
                )

    def login(self, data: Credentials, peer: str):
        self.throttle(data.username, peer)
        user = self.users.find_one({"username": data.username})
        valid = check_password(
            data.password.get_secret_value(), user.get("password_hash") if user else None
        )
        if not valid or not user or not user["active"]:
            raise HTTPException(
                401, "Invalid username or password", headers={"WWW-Authenticate": "Bearer"}
            )
        token = secrets.token_urlsafe(32)
        expires = datetime.now(UTC) + timedelta(hours=self.settings.session_hours)
        self.sessions.insert_one(
            {
                "_id": token_hash(token),
                "user_id": user["_id"],
                "auth_version": user["auth_version"],
                "expires_at": expires,
            }
        )
        return SessionResult(access_token=token, expires_at=expires, user=public_user(user))

    def authenticate(self, token: str):
        session = self.sessions.find_one(
            {"_id": token_hash(token), "expires_at": {"$gt": datetime.now(UTC)}}
        )
        user = (
            self.users.find_one(
                {"_id": session["user_id"], "active": True, "auth_version": session["auth_version"]}
            )
            if session
            else None
        )
        if not user:
            raise HTTPException(
                401, "Invalid or expired session", headers={"WWW-Authenticate": "Bearer"}
            )
        return Principal(
            user_id=user["_id"],
            username=user["username"],
            role=user["role"],
            session_hash=session["_id"],
        )

    def update_user(self, user_id: str, data: UserPatch, actor: str):
        existing = self.users.find_one({"_id": user_id})
        if not existing:
            raise HTTPException(404, "User not found")
        if existing["revision"] != data.expected_revision:
            raise HTTPException(409, "User changed; reload before editing")
        if len(existing["history"]) >= 500:
            raise HTTPException(409, "User history limit reached; archive through maintenance")
        values = data.model_dump(exclude_none=True, exclude={"expected_revision", "password"})
        if existing["role"] == "admin" and (
            values.get("role", "admin") != "admin" or values.get("active") is False
        ):
            raise HTTPException(
                409, "Administrator demotion or deactivation requires offline administration"
            )
        changed = dict(values)
        if data.password:
            values["password_hash"] = hash_password(data.password.get_secret_value())
            changed["password_changed"] = True
        if not values:
            raise HTTPException(422, "Provide at least one change")
        result = self.users.find_one_and_update(
            {"_id": user_id, "revision": data.expected_revision, "history.499": {"$exists": False}},
            {
                "$set": values,
                "$inc": {"revision": 1, "auth_version": 1},
                "$push": {
                    "history": {
                        "actor_id": actor,
                        "at": datetime.now(UTC),
                        "action": "updated",
                        "changes": changed,
                    }
                },
            },
            return_document=ReturnDocument.AFTER,
        )
        if not result:
            raise HTTPException(409, "User changed; reload before editing")
        return public_user(result)
