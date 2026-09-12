from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, Response

from app.alerts import AlertHistoryEntry, AlertNote, AlertRecord, AlertUpdate, NoteCreate
from app.dashboard import host_detail, host_record, summary
from app.endpoints import (
    EndpointCreate,
    EndpointCredential,
    EndpointPatch,
    EndpointRecord,
    Heartbeat,
    KeyRotation,
    public_endpoint,
)
from app.identity import (
    Credentials,
    PasswordChange,
    Principal,
    SessionResult,
    UserCreate,
    UserPatch,
    UserRecord,
    check_password,
    public_user,
)
from app.routes import Repository
from app.security import (
    require_admin,
    require_analyst,
    require_collector,
    require_editor,
    require_user,
)

router = APIRouter(prefix="/api/v1")
User = Annotated[Principal, Depends(require_user)]
Editor = Annotated[Principal, Depends(require_editor)]
Admin = Annotated[Principal, Depends(require_admin)]
AlertId = Annotated[str, Path(pattern=r"^[0-9a-fA-F]{24}$")]


@router.post("/auth/login", response_model=SessionResult, tags=["authentication"])
def login(data: Credentials, request: Request, repository: Repository):
    peer = request.client.host if request.client else "unknown"
    return repository.identity.login(data, peer)


@router.get("/auth/me", response_model=UserRecord, tags=["authentication"])
def me(user: User, repository: Repository):
    return public_user(repository.identity.users.find_one({"_id": user.user_id}))


@router.post("/auth/logout", status_code=204, tags=["authentication"])
def logout(user: User, repository: Repository):
    repository.identity.sessions.delete_one({"_id": user.session_hash})
    return Response(status_code=204)


@router.post("/auth/password", response_model=UserRecord, tags=["authentication"])
def change_password(data: PasswordChange, user: User, repository: Repository, request: Request):
    repository.identity.throttle(
        user.username, request.client.host if request.client else "unknown"
    )
    row = repository.identity.users.find_one({"_id": user.user_id})
    if not check_password(data.current_password.get_secret_value(), row["password_hash"]):
        raise HTTPException(401, "Current password is incorrect")
    return repository.identity.update_user(
        user.user_id,
        UserPatch(expected_revision=row["revision"], password=data.new_password),
        user.user_id,
    )


@router.post("/users", status_code=201, response_model=UserRecord, tags=["users"])
def create_user(data: UserCreate, admin: Admin, repository: Repository):
    return repository.identity.create_user(data, admin.user_id)


@router.get("/users", tags=["users"])
def users(
    admin: Admin,
    repository: Repository,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    after: UUID | None = None,
):
    query = {"_id": {"$gt": str(after)}} if after else {}
    rows = list(
        repository.identity.users.find(query, {"password_hash": 0, "history": 0})
        .sort("_id", 1)
        .limit(limit + 1)
        .max_time_ms(3000)
    )
    return {
        "items": [public_user(row) for row in rows[:limit]],
        "next_cursor": rows[limit - 1]["_id"] if len(rows) > limit else None,
    }


@router.get("/users/directory", tags=["users"])
def directory(
    user: User,
    repository: Repository,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    after: UUID | None = None,
):
    query = {"active": True, "role": {"$in": ["analyst", "admin"]}}
    if after:
        query["_id"] = {"$gt": str(after)}
    rows = list(
        repository.identity.users.find(query, {"username": 1, "role": 1})
        .sort("_id", 1)
        .limit(limit + 1)
        .max_time_ms(3000)
    )
    return {
        "items": [
            {"id": row["_id"], "username": row["username"], "role": row["role"]}
            for row in rows[:limit]
        ],
        "next_cursor": rows[limit - 1]["_id"] if len(rows) > limit else None,
    }


@router.patch("/users/{user_id}", response_model=UserRecord, tags=["users"])
def update_user(user_id: UUID, data: UserPatch, admin: Admin, repository: Repository):
    return repository.identity.update_user(str(user_id), data, admin.user_id)


@router.get("/users/{user_id}/history", tags=["users"])
def user_history(user_id: UUID, admin: Admin, repository: Repository):
    row = repository.identity.users.find_one({"_id": str(user_id)}, {"history": 1})
    if not row:
        raise HTTPException(404, "User not found")
    return {"items": row["history"]}


@router.post("/endpoints", status_code=201, response_model=EndpointCredential, tags=["endpoints"])
def enroll(data: EndpointCreate, admin: Admin, repository: Repository):
    return repository.endpoints.create(data, admin.user_id)


@router.get("/endpoints", tags=["endpoints"])
def endpoints(
    admin: Admin,
    repository: Repository,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    after: UUID | None = None,
):
    query = {"_id": {"$gt": str(after)}} if after else {}
    rows = list(
        repository.endpoints.collection.find(query, {"key_hash": 0, "history": 0})
        .sort("_id", 1)
        .limit(limit + 1)
        .max_time_ms(3000)
    )
    return {
        "items": [public_endpoint(row) for row in rows[:limit]],
        "next_cursor": rows[limit - 1]["_id"] if len(rows) > limit else None,
    }


@router.patch("/endpoints/{endpoint_id}", response_model=EndpointRecord, tags=["endpoints"])
def change_endpoint(endpoint_id: UUID, data: EndpointPatch, admin: Admin, repository: Repository):
    return repository.endpoints.update(
        str(endpoint_id), data.expected_revision, admin.user_id, active=data.active
    )


@router.post(
    "/endpoints/{endpoint_id}/rotate-key", response_model=EndpointCredential, tags=["endpoints"]
)
def rotate_endpoint(endpoint_id: UUID, data: KeyRotation, admin: Admin, repository: Repository):
    return repository.endpoints.update(
        str(endpoint_id), data.expected_revision, admin.user_id, rotate=True
    )


@router.get("/endpoints/{endpoint_id}/history", tags=["endpoints"])
def endpoint_history(endpoint_id: UUID, admin: Admin, repository: Repository):
    row = repository.endpoints.collection.find_one({"_id": str(endpoint_id)}, {"history": 1})
    if not row:
        raise HTTPException(404, "Endpoint not found")
    return {"items": row["history"]}


@router.post("/endpoints/heartbeat", tags=["endpoints"])
def heartbeat(
    data: Heartbeat,
    principal: Annotated[Principal, Depends(require_collector)],
    repository: Repository,
):
    repository.endpoints.check_scope(principal, data.endpoint_id, data.os.value)
    repository.endpoints.observe(data.endpoint_id, data.hostname, data.os.value, heartbeat=data)
    return {"status": "accepted"}


@router.patch("/alerts/{record_id}", response_model=AlertRecord, tags=["investigations"])
def update_alert(record_id: AlertId, data: AlertUpdate, user: Editor, repository: Repository):
    if data.assigned_to:
        assignee = repository.identity.users.find_one(
            {"_id": str(data.assigned_to), "active": True, "role": {"$in": ["analyst", "admin"]}}
        )
        if not assignee:
            raise HTTPException(422, "Assignee must be an active analyst or administrator")
    return repository.alerts.update(record_id, data, user.user_id)


@router.post(
    "/alerts/{record_id}/notes", status_code=201, response_model=AlertNote, tags=["investigations"]
)
def add_note(record_id: AlertId, data: NoteCreate, user: Editor, repository: Repository):
    return repository.alerts.add_note(record_id, data, user.user_id)


@router.get(
    "/alerts/{record_id}/notes",
    response_model=list[AlertNote],
    dependencies=[Depends(require_analyst)],
    tags=["investigations"],
)
def notes(record_id: AlertId, repository: Repository):
    return repository.alerts.workflow_document(record_id).get("notes", [])


@router.get(
    "/alerts/{record_id}/history", dependencies=[Depends(require_analyst)], tags=["investigations"]
)
def history(
    record_id: AlertId,
    repository: Repository,
    after_revision: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
):
    rows = [
        row
        for row in repository.alerts.workflow_document(record_id).get("history", [])
        if row["revision"] > after_revision
    ]
    return {
        "items": [AlertHistoryEntry(**row) for row in rows[:limit]],
        "next_revision": rows[limit - 1]["revision"] if len(rows) > limit else None,
    }


@router.get("/dashboard/summary", dependencies=[Depends(require_analyst)], tags=["dashboard"])
def dashboard_summary(repository: Repository, hours: Annotated[int, Query(ge=1, le=168)] = 24):
    return summary(repository, hours)


@router.get("/hosts", dependencies=[Depends(require_analyst)], tags=["hosts"])
def hosts(
    repository: Repository,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    after: Annotated[str | None, Query(max_length=255)] = None,
):
    query = {"_id": {"$gt": after}} if after else {}
    rows = list(
        repository.endpoints.hosts.find(query).sort("_id", 1).limit(limit + 1).max_time_ms(3000)
    )
    return {
        "items": [host_record(row) for row in rows[:limit]],
        "next_cursor": rows[limit - 1]["_id"] if len(rows) > limit else None,
    }


@router.get("/hosts/{endpoint_id}", dependencies=[Depends(require_analyst)], tags=["hosts"])
def host(endpoint_id: Annotated[str, Path(min_length=1, max_length=255)], repository: Repository):
    return host_detail(repository, endpoint_id)
