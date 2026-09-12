from datetime import UTC, datetime
from uuid import uuid4

import pytest

from app.identity import token_hash

pytestmark = pytest.mark.integration


def enroll(client, headers):
    data = {"endpoint_id": str(uuid4()), "hostname": "WIN-TEST", "os": "windows"}
    result = client.post("/api/v1/endpoints", json=data, headers=headers)
    assert result.status_code == 201, result.text
    return data, result.json()


def test_endpoint_key_is_hashed_scoped_and_cannot_read(managed, payload):
    _, repo, client, users = managed
    data, result = enroll(client, users["admin"][1])
    key = result["api_key"]
    stored = repo.endpoints.collection.find_one({"_id": data["endpoint_id"]})
    assert stored["key_hash"] == token_hash(key) and key not in str(stored)
    headers = {"X-API-Key": key}
    event = {
        **payload,
        "endpoint_id": data["endpoint_id"],
        "timestamp": datetime.now(UTC).isoformat(),
    }
    assert client.post("/api/v1/events", headers=headers, json=event).status_code == 201
    assert client.post("/api/v1/events", headers=headers, json=event).status_code == 200
    assert client.get("/api/v1/events", headers=headers).status_code == 401
    assert (
        client.post(
            "/api/v1/events", headers=headers, json={**event, "endpoint_id": str(uuid4())}
        ).status_code
        == 403
    )
    assert (
        client.post("/api/v1/events", headers=headers, json={**event, "os": "macos"}).status_code
        == 403
    )
    assert repo.collection.count_documents({}) == 1
    listing = client.get("/api/v1/endpoints", headers=users["admin"][1]).text
    assert key not in listing and stored["key_hash"] not in listing


def test_rotation_revocation_and_stale_updates(managed, payload):
    _, _, client, users = managed
    data, result = enroll(client, users["admin"][1])
    path = "/api/v1/endpoints/" + data["endpoint_id"]
    rotated = client.post(
        path + "/rotate-key", headers=users["admin"][1], json={"expected_revision": 0}
    )
    assert rotated.status_code == 200
    event = {**payload, "endpoint_id": data["endpoint_id"]}
    assert (
        client.post(
            "/api/v1/events", headers={"X-API-Key": result["api_key"]}, json=event
        ).status_code
        == 401
    )
    new_headers = {"X-API-Key": rotated.json()["api_key"]}
    assert client.post("/api/v1/events", headers=new_headers, json=event).status_code == 201
    assert (
        client.patch(
            path, headers=users["admin"][1], json={"expected_revision": 0, "active": False}
        ).status_code
        == 409
    )
    assert (
        client.patch(
            path, headers=users["admin"][1], json={"expected_revision": 1, "active": False}
        ).status_code
        == 200
    )
    assert client.post("/api/v1/events", headers=new_headers, json=event).status_code == 401
    history = client.get(path + "/history", headers=users["admin"][1]).json()["items"]
    assert [item["action"] for item in history] == ["enrolled", "key_rotated", "revoked"]


def test_heartbeat_uses_server_time_and_cannot_impersonate(managed):
    _, repo, client, users = managed
    data, result = enroll(client, users["admin"][1])
    heartbeat = {**data, "collector_version": "test", "pending": 3, "rejected": 0}
    headers = {"X-API-Key": result["api_key"]}
    before = datetime.now(UTC)
    assert (
        client.post("/api/v1/endpoints/heartbeat", headers=headers, json=heartbeat).status_code
        == 200
    )
    stored = repo.endpoints.hosts.find_one({"_id": data["endpoint_id"]})
    assert abs((stored["last_heartbeat_at"] - before).total_seconds()) < 5
    assert stored["pending"] == 3
    assert (
        client.post(
            "/api/v1/endpoints/heartbeat",
            headers=headers,
            json={**heartbeat, "endpoint_id": str(uuid4())},
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/api/v1/endpoints/heartbeat",
            headers=headers,
            json={**heartbeat, "last_seen_at": "2099-01-01"},
        ).status_code
        == 422
    )


def test_enrollment_requires_admin_and_does_not_reissue_existing_keys(managed):
    _, _, client, users = managed
    data, _ = enroll(client, users["admin"][1])
    assert client.post("/api/v1/endpoints", headers=users["admin"][1], json=data).status_code == 409
    for role in ("viewer", "analyst"):
        assert (
            client.post("/api/v1/endpoints", headers=users[role][1], json=data).status_code == 403
        )


def test_legacy_auth_can_be_disabled_without_disabling_endpoint_keys(
    managed, payload, analyst_headers, collector_headers
):
    settings, _, client, users = managed
    data, result = enroll(client, users["admin"][1])
    settings.allow_legacy_keys = False
    assert client.get("/api/v1/events", headers=analyst_headers).status_code == 401
    assert client.post("/api/v1/events", headers=collector_headers, json=payload).status_code == 401
    assert (
        client.post(
            "/api/v1/events",
            headers={"X-API-Key": result["api_key"]},
            json={**payload, "endpoint_id": data["endpoint_id"]},
        ).status_code
        == 201
    )
    assert client.get("/api/v1/events", headers=users["viewer"][1]).status_code == 200
