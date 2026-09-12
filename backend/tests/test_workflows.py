from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from bson import ObjectId

from app.alerts import AlertUpdate
from app.detections.worker import DetectionWorker
from app.models import EventInput

pytestmark = pytest.mark.integration


@pytest.fixture
def case(managed, payload):
    settings, repo, client, users = managed
    event, _ = repo.insert(
        EventInput.model_validate(
            {
                **payload,
                "timestamp": datetime.now(UTC),
                "event_type": "security_log_cleared",
                "event_code": 1102,
            }
        )
    )
    assert DetectionWorker(repo, settings).process_one()
    alert = repo.alerts.collection.find_one({})
    return repo, client, users, str(alert["_id"]), event


def test_status_assignment_notes_and_audit(case):
    repo, client, users, alert_id, event = case
    user, headers = users["analyst"]
    path = "/api/v1/alerts/" + alert_id
    response = client.patch(
        path,
        headers=headers,
        json={"expected_revision": 0, "status": "investigating", "assigned_to": user.id},
    )
    assert response.status_code == 200
    assert response.json()["revision"] == 1 and response.json()["assigned_to"] == user.id
    note = {"expected_revision": 1, "note_id": str(uuid4()), "text": "Synthetic analyst finding"}
    assert client.post(path + "/notes", headers=headers, json=note).status_code == 201
    assert client.post(path + "/notes", headers=headers, json=note).status_code == 201
    assert (
        client.post(path + "/notes", headers=headers, json={**note, "text": "changed"}).status_code
        == 409
    )
    resolved = client.patch(
        path, headers=headers, json={"expected_revision": 2, "status": "resolved"}
    )
    assert resolved.status_code == 200 and resolved.json()["note_count"] == 1
    stored = repo.alerts.collection.find_one({"_id": ObjectId(alert_id)})
    assert stored["related_event_ids"] == [event.id]
    history = client.get(path + "/history", headers=headers).json()["items"]
    assert [entry["revision"] for entry in history] == [1, 2, 3]
    assert all(entry["actor_id"] == user.id for entry in history)
    assert history[1]["changes"] == {"note_id": note["note_id"]}
    assert len(client.get(path + "/notes", headers=headers).json()) == 1
    page = client.get(
        "/api/v1/alerts", params={"status": "resolved", "assigned_to": user.id}, headers=headers
    ).json()
    assert [row["id"] for row in page["items"]] == [alert_id]


def test_stale_concurrent_edits_cannot_overwrite(case):
    repo, _, users, alert_id, _ = case
    from fastapi import HTTPException

    def edit(status):
        try:
            repo.alerts.update(
                alert_id, AlertUpdate(expected_revision=0, status=status), users["analyst"][0].id
            )
            return 200
        except HTTPException as exc:
            return exc.status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(edit, ["investigating", "false_positive"]))
    assert sorted(results) == [200, 409]
    assert len(repo.alerts.workflow_document(alert_id)["history"]) == 1


def test_viewer_and_legacy_key_cannot_write(case, analyst_headers, collector_headers):
    _, client, users, alert_id, _ = case
    path = "/api/v1/alerts/" + alert_id
    for headers, expected in (
        (users["viewer"][1], 403),
        (analyst_headers, 403),
        (collector_headers, 401),
        ({}, 401),
    ):
        assert (
            client.patch(
                path, headers=headers, json={"expected_revision": 0, "status": "resolved"}
            ).status_code
            == expected
        )
    assert client.get(path + "/history", headers=users["viewer"][1]).status_code == 200


def test_invalid_assignment_and_immutable_fields_are_rejected(case):
    _, client, users, alert_id, _ = case
    path = "/api/v1/alerts/" + alert_id
    for assignee in (str(uuid4()), users["viewer"][0].id):
        assert (
            client.patch(
                path,
                headers=users["analyst"][1],
                json={"expected_revision": 0, "assigned_to": assignee},
            ).status_code
            == 422
        )
    assert (
        client.patch(
            path, headers=users["analyst"][1], json={"expected_revision": 0, "severity": "info"}
        ).status_code
        == 422
    )
    assert (
        client.patch(
            path, headers=users["analyst"][1], json={"expected_revision": 0, "status": None}
        ).status_code
        == 422
    )


def test_existing_alert_without_revision_migrates_on_first_edit(case):
    repo, client, users, alert_id, _ = case
    repo.alerts.collection.update_one(
        {"_id": ObjectId(alert_id)}, {"$unset": {"revision": "", "note_count": ""}}
    )
    result = client.patch(
        "/api/v1/alerts/" + alert_id,
        headers=users["analyst"][1],
        json={"expected_revision": 0, "status": "investigating"},
    )
    assert result.status_code == 200 and result.json()["revision"] == 1


def test_notes_capacity_and_history_pagination(case):
    repo, client, users, alert_id, _ = case
    path = "/api/v1/alerts/" + alert_id
    for revision, status in enumerate(("investigating", "resolved", "open")):
        assert (
            client.patch(
                path,
                headers=users["analyst"][1],
                json={"expected_revision": revision, "status": status},
            ).status_code
            == 200
        )
    page = client.get(path + "/history?limit=1", headers=users["analyst"][1]).json()
    assert page["next_revision"] == 1
    next_page = client.get(
        path + "/history?after_revision=1&limit=1", headers=users["analyst"][1]
    ).json()
    assert next_page["items"][0]["revision"] == 2
    repo.alerts.collection.update_one(
        {"_id": ObjectId(alert_id)}, {"$set": {"notes": [{"id": str(uuid4())} for _ in range(100)]}}
    )
    assert (
        client.post(
            path + "/notes",
            headers=users["analyst"][1],
            json={"expected_revision": 3, "note_id": str(uuid4()), "text": "one more"},
        ).status_code
        == 409
    )
