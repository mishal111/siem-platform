from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from unittest.mock import patch
from uuid import uuid4

import pytest
from bson import ObjectId
from fastapi.testclient import TestClient

from app.alerts import AlertFilters
from app.detections.engine import DetectionEngine
from app.detections.worker import DetectionWorker
from app.main import create_app
from app.models import EventInput

pytestmark = pytest.mark.integration


@pytest.fixture
def lab(mongo_repository):
    settings, repository = mongo_repository
    # A fixed bucket boundary in the recent past makes suppression expectations repeatable.
    now = datetime.now(UTC)
    base = datetime.fromtimestamp(int(now.timestamp()) // 300 * 300, UTC) - timedelta(minutes=15)

    def insert(seconds=0, event_type="login_failure", **overrides):
        values = {
            "event_uid": str(uuid4()),
            "endpoint_id": "test-endpoint",
            "hostname": "TEST-HOST",
            "os": "windows",
            "source": "Security",
            "event_type": event_type,
            "event_code": 4625 if event_type == "login_failure" else 4624,
            "username": "alice",
            "source_ip": "192.0.2.20",
            "user_domain": "LAB",
            "timestamp": base + timedelta(seconds=seconds),
            "message": "Synthetic detection fixture",
            **overrides,
        }
        record, _ = repository.insert(EventInput.model_validate(values))
        return repository.collection.find_one({"_id": ObjectId(record.id)})

    worker = DetectionWorker(repository, settings)

    def drain():
        for _ in range(100):
            if not worker.process_one():
                return
        raise AssertionError("Detection jobs failed to drain")

    return settings, repository, worker, insert, drain


def test_five_failures_trigger_once_and_evidence_is_bounded(lab):
    _, repo, _, insert, drain = lab
    for second in (0, 10, 20, 30):
        insert(second)
    drain()
    assert repo.alerts.collection.count_documents({}) == 0
    insert(40)
    drain()
    alert = repo.alerts.collection.find_one({})
    assert alert["rule_id"] == "AUTH-BRUTE-001"
    assert alert["event_count"] == alert["failure_count"] == 5
    assert alert["mitre_technique"] == "T1110" and alert["severity"] == "high"
    assert alert["trigger_event_id"] in alert["related_event_ids"]
    original = alert.copy()
    insert(50)
    insert(60)
    drain()
    assert repo.alerts.collection.count_documents({}) == 1
    assert repo.alerts.collection.find_one({}) == original


@pytest.mark.parametrize("last,expected", [(300, 1), (300.001, 0)])
def test_five_minute_boundary_is_inclusive(lab, last, expected):
    _, repo, _, insert, drain = lab
    for second in (0, 10, 20, 30, last):
        insert(second)
    drain()
    assert repo.alerts.collection.count_documents({}) == expected


def test_rolling_window_spans_suppression_bucket_boundary(lab):
    _, repo, _, insert, drain = lab
    for second in (280, 290, 300, 310, 320):
        insert(second)
    drain()
    assert repo.alerts.collection.count_documents({"rule_id": "AUTH-BRUTE-001"}) == 1


@pytest.mark.parametrize(
    "field,value",
    [
        ("endpoint_id", "other-host"),
        ("username", "bob"),
        ("user_domain", "OTHER"),
        ("source_ip", "192.0.2.21"),
        ("source", "different-source"),
        ("os", "macos"),
    ],
)
def test_unrelated_authentication_contexts_do_not_combine(lab, field, value):
    _, repo, _, insert, drain = lab
    for second in (0, 10, 20, 30):
        insert(second)
    insert(40, **{field: value})
    drain()
    assert repo.alerts.collection.count_documents({}) == 0


@pytest.mark.parametrize(
    "values", [{"username": None}, {"username": "<private>"}, {"source_ip": None}]
)
def test_missing_authentication_context_is_skipped(lab, values):
    _, repo, _, insert, drain = lab
    for i in range(5):
        insert(i, **values)
    drain()
    assert repo.alerts.collection.count_documents({}) == 0
    assert (
        repo.collection.count_documents({"detection_skip_reason": "missing_authentication_context"})
        == 5
    )


def test_success_before_failures_arrive_is_revisited(lab):
    _, repo, _, insert, drain = lab
    success = insert(90, "login_success")
    drain()
    for second in (40, 10, 30, 0, 20):
        insert(second)
        drain()
    assert repo.alerts.collection.count_documents({}) == 2
    alert = repo.alerts.collection.find_one({"rule_id": "AUTH-SUCCESS-001"})
    assert alert["trigger_event_id"] == str(success["_id"])
    assert alert["event_count"] == 6 and alert["failure_count"] == 5
    assert str(success["_id"]) in alert["related_event_ids"]


@pytest.mark.parametrize("success_second,expected", [(600, 1), (600.001, 0)])
def test_ten_minute_success_boundary(lab, success_second, expected):
    _, repo, _, insert, drain = lab
    for i in (0, 10, 20, 30, 40):
        insert(i)
    insert(success_second, "login_success")
    drain()
    assert repo.alerts.collection.count_documents({"rule_id": "AUTH-SUCCESS-001"}) == expected


def test_failures_at_same_time_as_success_do_not_precede_it(lab):
    _, repo, _, insert, drain = lab
    for _ in range(5):
        insert(30)
    insert(30, "login_success")
    drain()
    assert repo.alerts.collection.count_documents({"rule_id": "AUTH-SUCCESS-001"}) == 0
    assert repo.alerts.collection.count_documents({"rule_id": "AUTH-BRUTE-001"}) == 1


@pytest.mark.parametrize(
    "os,code,source,expected",
    [
        ("windows", 1102, "Security", 1),
        ("macos", 1102, "Security", 0),
        ("windows", 9999, "Security", 0),
        ("windows", 1102, "Application", 0),
    ],
)
def test_log_clearing_requires_windows_security_1102(lab, os, code, source, expected):
    _, repo, _, insert, drain = lab
    insert(0, "security_log_cleared", os=os, event_code=code, source=source)
    drain()
    assert repo.alerts.collection.count_documents({}) == expected
    if expected:
        alert = repo.alerts.collection.find_one({})
        assert alert["severity"] == "critical" and alert["mitre_technique"] == "T1070.001"


def test_outside_allowed_clock_range_is_stored_but_skipped(lab):
    _, repo, _, insert, drain = lab
    now = datetime.now(UTC)
    insert(event_type="security_log_cleared", event_code=1102, timestamp=now - timedelta(days=2))
    insert(
        event_type="security_log_cleared", event_code=1102, timestamp=now + timedelta(minutes=10)
    )
    drain()
    assert repo.collection.count_documents({"processing_status": "skipped"}) == 2
    assert repo.alerts.collection.count_documents({}) == 0


def test_ineligible_failure_is_not_used_as_correlation_evidence(lab):
    _, repo, _, insert, drain = lab
    rows = [insert(i) for i in range(5)]
    repo.collection.update_one(
        {"_id": rows[0]["_id"]}, {"$set": {"received_at": rows[0]["timestamp"] + timedelta(days=2)}}
    )
    drain()
    assert repo.alerts.collection.count_documents({}) == 0


def test_processing_time_does_not_expire_previously_eligible_events(lab):
    _, repo, _, insert, drain = lab
    old = datetime.now(UTC) - timedelta(days=3)
    row = insert(event_type="security_log_cleared", event_code=1102, timestamp=old)
    repo.collection.update_one(
        {"_id": row["_id"]}, {"$set": {"received_at": old + timedelta(seconds=1)}}
    )
    drain()
    assert repo.alerts.collection.count_documents({}) == 1


def test_failure_after_alert_write_retries_without_duplicate(lab):
    _, repo, worker, insert, drain = lab
    insert(event_type="security_log_cleared", event_code=1102)
    with patch.object(
        worker, "finish", side_effect=RuntimeError("simulated crash after alert write")
    ):
        worker.process_one()
    assert repo.alerts.collection.count_documents({}) == 1
    assert repo.collection.find_one({})["processing_status"] == "pending"
    repo.collection.update_many({}, {"$unset": {"detection_next_attempt": ""}})
    drain()
    assert repo.alerts.collection.count_documents({}) == 1
    assert repo.collection.find_one({})["processing_status"] == "processed"


def test_expired_lease_is_recovered_and_old_worker_cannot_complete(lab):
    settings, repo, first, insert, _ = lab
    insert(event_type="security_log_cleared", event_code=1102)
    stale = first.claim()
    second = DetectionWorker(repo, settings)
    assert second.claim() is None
    repo.collection.update_one(
        {"_id": stale["_id"]},
        {"$set": {"processing_lease_until": datetime.now(UTC) - timedelta(seconds=1)}},
    )
    claimed = second.claim()
    assert claimed["processing_token"] != stale["processing_token"]
    first.finish(stale, None)
    assert repo.collection.find_one({})["processing_status"] == "processing"
    second.engine.evaluate(claimed)
    second.finish(claimed, None)
    assert repo.collection.find_one({})["processing_status"] == "processed"


def test_concurrent_evaluation_writes_one_alert(lab):
    settings, repo, _, insert, _ = lab
    row = insert(event_type="security_log_cleared", event_code=1102)
    with ThreadPoolExecutor(max_workers=4) as executor:
        list(executor.map(lambda _: DetectionEngine(repo, settings).evaluate(row), range(12)))
    assert repo.alerts.collection.count_documents({}) == 1


def test_concurrent_workers_claim_distinct_jobs(lab):
    settings, repo, _, insert, _ = lab
    for i in range(8):
        insert(i, "security_log_cleared", event_code=1102)
    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(
            executor.map(lambda _: DetectionWorker(repo, settings).process_one(), range(8))
        )
    assert all(results)
    assert repo.collection.count_documents({"processing_status": "processed"}) == 8
    assert repo.alerts.collection.count_documents({}) == 8


def test_repeated_errors_become_failed_without_blocking_other_events(lab):
    settings, repo, worker, insert, drain = lab
    first = insert(0, "security_log_cleared", event_code=1102)
    with patch.object(worker.engine, "evaluate", side_effect=ValueError("invalid stored record")):
        for _ in range(settings.detection_max_attempts):
            worker.process_one()
            repo.collection.update_one(
                {"_id": first["_id"]}, {"$unset": {"detection_next_attempt": ""}}
            )
    assert repo.collection.find_one({"_id": first["_id"]})["processing_status"] == "failed"
    insert(10, "security_log_cleared", event_code=1102)
    drain()
    assert repo.alerts.collection.count_documents({}) == 1


def test_alert_api_evidence_filters_and_pagination(lab, analyst_headers):
    settings, repo, _, insert, drain = lab
    for second in (0, 1, 2):
        insert(second, "security_log_cleared", event_code=1102)
    drain()
    with TestClient(create_app(settings)) as client:
        params = {"limit": 1, "endpoint_id": "test-endpoint", "severity": "critical"}
        ids = []
        while True:
            response = client.get("/api/v1/alerts", params=params, headers=analyst_headers)
            assert response.status_code == 200, response.text
            page = response.json()
            ids += [alert["id"] for alert in page["items"]]
            if not page["next_cursor"]:
                break
            params["cursor"] = page["next_cursor"]
        assert len(ids) == len(set(ids)) == 3
        record = client.get(f"/api/v1/alerts/{ids[0]}", headers=analyst_headers).json()
        assert "dedup_key" not in record
        evidence = client.get(f"/api/v1/alerts/{ids[0]}/events", headers=analyst_headers).json()
        assert [event["id"] for event in evidence["items"]] == record["related_event_ids"]
        assert evidence["missing_event_ids"] == []
        repo.collection.delete_one({"_id": ObjectId(record["related_event_ids"][0])})
        evidence = client.get(f"/api/v1/alerts/{ids[0]}/events", headers=analyst_headers).json()
        assert evidence["missing_event_ids"] == record["related_event_ids"]
        status = client.get("/api/v1/detections/status", headers=analyst_headers).json()
        assert status["worker_recent"] and status["events"]["processed"] == 2
        assert repo.search_alerts(AlertFilters(severity="high")).items == []
        assert repo.search_alerts(AlertFilters(start_time=datetime.now(UTC))).items == []
