from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, Response

from app.alerts import AlertEvidence, AlertFilters, AlertPage, AlertRecord
from app.detections.rules import catalog
from app.identity import Principal
from app.models import EventFilters, EventInput, EventPage, EventRecord, IngestResult
from app.repository import EventConflict, EventRepository, InvalidCursor
from app.security import require_analyst, require_collector

router = APIRouter(prefix="/api/v1")


def get_repository(request: Request) -> EventRepository:
    return request.app.state.repository


Repository = Annotated[EventRepository, Depends(get_repository)]


@router.get("/health", tags=["health"])
def health() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/health/ready", tags=["health"])
def ready(repository: Repository) -> dict[str, str]:
    repository.ping()
    return {"status": "ready"}


@router.post(
    "/events",
    response_model=IngestResult,
    status_code=201,
    tags=["events"],
    responses={
        200: {"description": "Identical event already stored"},
        409: {"description": "UID conflict"},
    },
)
def ingest(
    event: EventInput,
    response: Response,
    repository: Repository,
    principal: Annotated[Principal, Depends(require_collector)],
) -> IngestResult:
    if not principal.legacy:
        repository.endpoints.check_scope(principal, event.endpoint_id, event.os.value)
    try:
        record, duplicate = repository.insert(event)
    except EventConflict:
        raise HTTPException(409, "Event UID already exists with a different payload") from None
    if duplicate:
        response.status_code = 200
    repository.observe_endpoint(event, record.received_at)
    return IngestResult(event=record, duplicate=duplicate)


@router.get(
    "/events", response_model=EventPage, dependencies=[Depends(require_analyst)], tags=["events"]
)
def search(filters: Annotated[EventFilters, Query()], repository: Repository) -> EventPage:
    try:
        return repository.search(filters)
    except InvalidCursor:
        raise HTTPException(422, "Invalid pagination cursor") from None


@router.get(
    "/events/{record_id}",
    response_model=EventRecord,
    dependencies=[Depends(require_analyst)],
    tags=["events"],
)
def get_event(
    record_id: Annotated[str, Path(pattern=r"^[0-9a-fA-F]{24}$")], repository: Repository
) -> EventRecord:
    event = repository.get(record_id)
    if event is None:
        raise HTTPException(404, "Event not found")
    return event


@router.get(
    "/alerts", response_model=AlertPage, dependencies=[Depends(require_analyst)], tags=["alerts"]
)
def search_alerts(filters: Annotated[AlertFilters, Query()], repository: Repository) -> AlertPage:
    try:
        return repository.search_alerts(filters)
    except InvalidCursor:
        raise HTTPException(422, "Invalid pagination cursor") from None


@router.get(
    "/alerts/{record_id}",
    response_model=AlertRecord,
    dependencies=[Depends(require_analyst)],
    tags=["alerts"],
)
def get_alert(
    record_id: Annotated[str, Path(pattern=r"^[0-9a-fA-F]{24}$")], repository: Repository
) -> AlertRecord:
    alert = repository.get_alert(record_id)
    if alert is None:
        raise HTTPException(404, "Alert not found")
    return alert


@router.get(
    "/alerts/{record_id}/events",
    response_model=AlertEvidence,
    dependencies=[Depends(require_analyst)],
    tags=["alerts"],
)
def alert_events(
    record_id: Annotated[str, Path(pattern=r"^[0-9a-fA-F]{24}$")], repository: Repository
) -> AlertEvidence:
    evidence = repository.alert_evidence(record_id)
    if evidence is None:
        raise HTTPException(404, "Alert not found")
    return evidence


@router.get("/detections/rules", dependencies=[Depends(require_analyst)], tags=["detections"])
def detection_rules() -> list[dict]:
    return catalog()


@router.get("/detections/status", dependencies=[Depends(require_analyst)], tags=["detections"])
def detection_status(repository: Repository) -> dict:
    return repository.detection_status()
