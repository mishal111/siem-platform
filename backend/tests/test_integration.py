from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.models import EventInput

pytestmark = pytest.mark.integration


def test_real_ingestion_replay_conflict_and_reads(
    mongo_repository, payload, collector_headers, analyst_headers
):
    settings, repository = mongo_repository
    # The app owns its own client; the fixture retains a client for cleanup/assertions.
    with TestClient(create_app(settings)) as client:
        first = client.post("/api/v1/events", json=payload, headers=collector_headers)
        assert first.status_code == 201, first.text
        repeated = client.post("/api/v1/events", json=payload, headers=collector_headers)
        assert repeated.status_code == 200
        assert first.json()["event"] == repeated.json()["event"]
        record = first.json()["event"]
        assert repository.collection.count_documents({}) == 1
        stored = repository.collection.find_one({})
        assert stored["processing_status"] == "pending"
        assert "payload_hash" not in record and "processing_status" not in record
        response = client.get(f"/api/v1/events/{record['id']}", headers=analyst_headers)
        assert response.json() == record
        payload["message"] = "Changed event using the same UID"
        assert (
            client.post("/api/v1/events", json=payload, headers=collector_headers).status_code
            == 409
        )
    # A new API process/client sees previously persisted events.
    with TestClient(create_app(settings)) as restarted:
        page = restarted.get("/api/v1/events", headers=analyst_headers).json()
        assert page["items"][0]["id"] == record["id"]


def test_concurrent_duplicate_delivery(mongo_repository, payload):
    _, repository = mongo_repository
    event = EventInput.model_validate(payload)
    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(lambda _: repository.insert(event), range(16)))
    assert sum(not duplicate for _, duplicate in results) == 1
    assert len({record.id for record, _ in results}) == 1
    assert repository.collection.count_documents({}) == 1


def test_real_filters_and_tied_timestamp_pagination(mongo_repository, payload, analyst_headers):
    settings, repository = mongo_repository
    for index in range(7):
        repository.insert(
            EventInput.model_validate(
                {**payload, "event_uid": str(uuid4()), "username": "alice" if index < 5 else "bob"}
            )
        )
    with TestClient(create_app(settings)) as client:
        params = {"username": "alice", "event_code": 4625, "limit": 2}
        ids = []
        while True:
            response = client.get("/api/v1/events", params=params, headers=analyst_headers)
            assert response.status_code == 200, response.text
            page = response.json()
            ids.extend(record["id"] for record in page["items"])
            assert all(record["username"] == "alice" for record in page["items"])
            if page["next_cursor"] is None:
                break
            params["cursor"] = page["next_cursor"]
        assert len(ids) == len(set(ids)) == 5
        assert ids == sorted(ids, reverse=True)
        for filters in (
            {"hostname": "missing"},
            {"event_code": 4624},
            {"os": "macos"},
            {"source_ip": "192.168.1.21"},
            {"severity": "critical"},
            {"start_time": "2026-09-11T00:00:00Z"},
            {"end_time": "2026-09-09T00:00:00Z"},
        ):
            assert (
                client.get("/api/v1/events", params=filters, headers=analyst_headers).json()[
                    "items"
                ]
                == []
            )


def test_same_uid_on_different_endpoints_and_equivalent_timezone(mongo_repository, payload):
    _, repository = mongo_repository
    first, _ = repository.insert(EventInput.model_validate(payload))
    same_event = {**payload, "timestamp": "2026-09-10T07:00:00.123Z"}
    repeated, duplicate = repository.insert(EventInput.model_validate(same_event))
    assert duplicate and repeated == first
    different_endpoint = {**payload, "endpoint_id": "another-endpoint"}
    other, duplicate = repository.insert(EventInput.model_validate(different_endpoint))
    assert not duplicate and other.id != first.id
