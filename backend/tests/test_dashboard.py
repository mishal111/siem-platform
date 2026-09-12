from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from app.detections.worker import DetectionWorker

pytestmark = pytest.mark.integration


def test_empty_summary_is_zero_filled_and_access_controlled(managed, collector_headers):
    _, _, client, users = managed
    assert client.get("/api/v1/dashboard/summary").status_code == 401
    assert client.get("/api/v1/dashboard/summary", headers=collector_headers).status_code == 401
    response = client.get("/api/v1/dashboard/summary?hours=2", headers=users["viewer"][1])
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["event_count"] == body["alert_count"] == 0
    assert len(body["events_per_hour"]) == 3
    assert all(point["count"] == 0 for point in body["events_per_hour"])
    assert (
        client.get("/api/v1/dashboard/summary?hours=169", headers=users["viewer"][1]).status_code
        == 422
    )


def test_summary_host_detail_and_time_basis(managed, collector_headers, payload):
    settings, repo, client, users = managed
    endpoint = str(uuid4())
    event = {
        **payload,
        "endpoint_id": endpoint,
        "timestamp": datetime.now(UTC).isoformat(),
        "event_type": "account_created",
        "event_code": 4720,
    }
    assert client.post("/api/v1/events", headers=collector_headers, json=event).status_code == 201
    assert DetectionWorker(repo, settings).process_one()
    body = client.get("/api/v1/dashboard/summary", headers=users["viewer"][1]).json()
    assert body["event_count"] == body["alert_count"] == 1
    assert body["events_by_os"] == {"windows": 1}
    assert body["alerts_by_rule"] == {"WIN-ACCOUNT-001": 1}
    assert body["alerts_by_status"] == {"open": 1}
    assert sum(point["count"] for point in body["events_per_hour"]) == 1
    assert body["top_hosts"] == [{"endpoint_id": endpoint, "count": 1}]
    hosts = client.get("/api/v1/hosts", headers=users["viewer"][1]).json()["items"]
    assert hosts[0]["endpoint_id"] == endpoint and hosts[0]["last_heartbeat_at"] is None
    detail = client.get("/api/v1/hosts/" + endpoint, headers=users["viewer"][1]).json()
    assert detail["event_count"] == detail["alert_count"] == 1
    assert len(detail["recent_events"]) == len(detail["recent_alerts"]) == 1
    repo.collection.update_many(
        {}, {"$set": {"received_at": datetime.now(UTC) - timedelta(days=8)}}
    )
    assert (
        client.get("/api/v1/dashboard/summary", headers=users["viewer"][1]).json()["event_count"]
        == 0
    )
    assert client.get("/api/v1/hosts/missing", headers=users["viewer"][1]).status_code == 404


def test_host_pagination_is_bounded_and_stable(managed, collector_headers, payload):
    _, _, client, users = managed
    for _ in range(3):
        assert (
            client.post(
                "/api/v1/events",
                headers=collector_headers,
                json={**payload, "endpoint_id": str(uuid4()), "event_uid": str(uuid4())},
            ).status_code
            == 201
        )
    found = []
    cursor = None
    while True:
        params = {"limit": 1}
        if cursor:
            params["after"] = cursor
        page = client.get("/api/v1/hosts", headers=users["viewer"][1], params=params).json()
        found.extend(row["endpoint_id"] for row in page["items"])
        cursor = page["next_cursor"]
        if not cursor:
            break
    assert len(found) == len(set(found)) == 3
