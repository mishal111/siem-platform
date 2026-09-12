import secrets
from typing import Annotated

from fastapi import HTTPException, Request, Security
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer

from app.identity import Principal

collector_header = APIKeyHeader(name="X-API-Key", scheme_name="CollectorKey", auto_error=False)
analyst_header = APIKeyHeader(name="X-API-Key", scheme_name="AnalystKey", auto_error=False)
bearer = HTTPBearer(auto_error=False)


def verify_key(provided: str | None, expected: str) -> None:
    if provided is None or not secrets.compare_digest(provided.encode(), expected.encode()):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


def require_collector(
    request: Request, key: Annotated[str | None, Security(collector_header)]
) -> Principal:
    settings = request.app.state.settings
    if not key or len(key) > 512:
        raise HTTPException(401, "Invalid or missing collector key")
    if settings.allow_legacy_keys and secrets.compare_digest(
        key.encode(), settings.collector_api_key.get_secret_value().encode()
    ):
        return Principal(legacy=True)
    if not key.startswith("siem_agent_"):
        raise HTTPException(401, "Invalid or missing collector key")
    return request.app.state.repository.endpoints.authenticate(key)


def require_analyst(
    request: Request,
    key: Annotated[str | None, Security(analyst_header)],
    credentials: Annotated[HTTPAuthorizationCredentials | None, Security(bearer)] = None,
) -> Principal:
    if credentials:
        if len(credentials.credentials) > 512:
            raise HTTPException(401, "Invalid session")
        return request.app.state.repository.identity.authenticate(credentials.credentials)
    if request.headers.get("authorization"):
        raise HTTPException(401, "Use a Bearer session token")
    settings = request.app.state.settings
    if settings.allow_legacy_keys:
        verify_key(key, settings.analyst_api_key.get_secret_value())
        return Principal(legacy=True)
    raise HTTPException(401, "User login required", headers={"WWW-Authenticate": "Bearer"})


def require_user(principal: Annotated[Principal, Security(require_analyst)]) -> Principal:
    if principal.legacy:
        raise HTTPException(403, "Sign in with a user account for this operation")
    return principal


def require_editor(principal: Annotated[Principal, Security(require_user)]) -> Principal:
    if principal.role not in ("analyst", "admin"):
        raise HTTPException(403, "Analyst role required")
    return principal


def require_admin(principal: Annotated[Principal, Security(require_user)]) -> Principal:
    if principal.role != "admin":
        raise HTTPException(403, "Administrator role required")
    return principal
