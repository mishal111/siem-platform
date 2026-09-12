import pytest
from pymongo.errors import AutoReconnect

from app.repository import EventConflict, InvalidCursor


def test_health_and_readiness(client, repository):
    assert client.get("/api/v1/health").json() == {"status": "ok"}
    assert client.get("/api/v1/health/ready").json() == {"status": "ready"}
    repository.ping.assert_called_once()


def test_ingestion_and_duplicate_status(client, repository, payload, record, collector_headers):
    response = client.post("/api/v1/events", json=payload, headers=collector_headers)
    assert response.status_code == 201
    assert response.json()["duplicate"] is False
    assert response.json()["event"]["timestamp"] == "2026-09-10T07:00:00.123000Z"
    assert response.headers["x-request-id"]
    repository.insert.return_value = record, True
    response = client.post("/api/v1/events", json=payload, headers=collector_headers)
    assert response.status_code == 200
    assert response.json()["duplicate"] is True


def test_reused_uid_conflict(client, repository, payload, collector_headers):
    repository.insert.side_effect = EventConflict
    response = client.post("/api/v1/events", json=payload, headers=collector_headers)
    assert response.status_code == 409


@pytest.mark.parametrize("key", [None, "wrong-key", "non-ascii-\u00e9"])
def test_missing_or_invalid_keys(client, repository, payload, key):
    # HTTP header values use Latin-1; exercise malformed Unicode directly in the auth unit test.
    if key and not key.isascii():
        from fastapi import HTTPException

        from app.security import verify_key

        with pytest.raises(HTTPException) as exc:
            verify_key(key, "expected")
        assert exc.value.status_code == 401
        return
    headers = {"X-API-Key": key} if key else {}
    assert client.post("/api/v1/events", json=payload, headers=headers).status_code == 401
    assert client.get("/api/v1/events", headers=headers).status_code == 401
    assert client.get("/api/v1/events/0123456789abcdef01234567", headers=headers).status_code == 401
    repository.insert.assert_not_called()
    repository.search.assert_not_called()


def test_keys_cannot_cross_roles(client, payload, collector_headers, analyst_headers):
    assert client.post("/api/v1/events", json=payload, headers=analyst_headers).status_code == 401
    assert client.get("/api/v1/events", headers=collector_headers).status_code == 401


@pytest.mark.parametrize(
    "field,value",
    [
        ("timestamp", "2026-09-10T12:30:00"),
        ("os", "linux"),
        ("source_ip", "not-an-ip"),
        ("event_uid", "not-a-uuid"),
        ("received_at", "2026-09-10T12:00:00Z"),
        ("processing_status", "complete"),
        ("event_code", 2**64),
        ("raw_event", {"huge": 2**64}),
        ("raw_event", {"bad\u0000key": "value"}),
    ],
)
def test_invalid_events_do_not_reach_storage(
    client, repository, payload, collector_headers, field, value
):
    payload[field] = value
    response = client.post("/api/v1/events", json=payload, headers=collector_headers)
    assert response.status_code == 422
    repository.insert.assert_not_called()
    assert all("input" not in error for error in response.json()["detail"])


@pytest.mark.parametrize("body", ['{"bad":', '{"value":NaN}', '{"value":Infinity}'])
def test_malformed_json(client, collector_headers, body):
    response = client.post(
        "/api/v1/events",
        content=body,
        headers={**collector_headers, "Content-Type": "application/json"},
    )
    assert response.status_code == 400


def test_payload_limit_and_encoding(client, repository, collector_headers):
    response = client.post("/api/v1/events", content=b"x" * 4097, headers=collector_headers)
    assert response.status_code == 413
    response = client.post(
        "/api/v1/events",
        content=b"small",
        headers={**collector_headers, "Content-Encoding": "gzip"},
    )
    assert response.status_code == 415
    repository.insert.assert_not_called()


@pytest.mark.parametrize(
    "query",
    [
        "limit=0",
        "limit=201",
        "limit=-1",
        "limit=hello",
        "source_ip=bad",
        "start_time=2026-09-10T00:00:00",
        "start_time=2026-09-11T00:00:00Z&end_time=2026-09-10T00:00:00Z",
        "unexpected=value",
    ],
)
def test_invalid_search(client, repository, analyst_headers, query):
    assert client.get("/api/v1/events?" + query, headers=analyst_headers).status_code == 422
    repository.search.assert_not_called()


def test_search_and_detail(client, repository, analyst_headers, record):
    response = client.get(
        "/api/v1/events?hostname=WIN11-LAB&event_code=4625&limit=5", headers=analyst_headers
    )
    assert response.status_code == 200
    assert response.json()["items"][0]["id"] == record.id
    filters = repository.search.call_args.args[0]
    assert (filters.hostname, filters.event_code, filters.limit) == ("WIN11-LAB", 4625, 5)
    assert client.get(f"/api/v1/events/{record.id}", headers=analyst_headers).status_code == 200
    repository.get.return_value = None
    assert client.get(f"/api/v1/events/{record.id}", headers=analyst_headers).status_code == 404
    assert client.get("/api/v1/events/not-an-id", headers=analyst_headers).status_code == 422


def test_invalid_cursor(client, repository, analyst_headers):
    repository.search.side_effect = InvalidCursor
    assert client.get("/api/v1/events?cursor=bad", headers=analyst_headers).status_code == 422


def test_database_outage_does_not_leak_details(
    client, repository, payload, collector_headers, analyst_headers, caplog
):
    error = AutoReconnect("mongodb://secret-user:secret-password@private-server")
    repository.ping.side_effect = error
    repository.insert.side_effect = error
    repository.search.side_effect = error
    responses = [
        client.get("/api/v1/health/ready"),
        client.post("/api/v1/events", json=payload, headers=collector_headers),
        client.get("/api/v1/events", headers=analyst_headers),
    ]
    for response in responses:
        assert response.status_code == 503
        assert response.headers["retry-after"] == "3"
        assert "secret-password" not in response.text
    assert "secret-password" not in caplog.text
    assert client.get("/api/v1/health").status_code == 200


def test_request_logging_omits_credentials_and_telemetry(
    client, payload, collector_headers, caplog
):
    caplog.set_level("INFO", logger="siem.http")
    payload["message"] = "sensitive-telemetry-marker"
    client.post("/api/v1/events", json=payload, headers=collector_headers)
    assert "http_request" in caplog.text
    assert "sensitive-telemetry-marker" not in caplog.text
    assert collector_headers["X-API-Key"] not in caplog.text
