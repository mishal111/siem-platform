from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from app.maintenance import backfill_hosts, retain
from app.models import EventInput

pytestmark = pytest.mark.integration


def old_event(repo, payload, age=200, status="processed"):
    now = datetime.now(UTC)
    event, _ = repo.insert(
        EventInput.model_validate(
            {**payload, "event_uid": str(uuid4()), "timestamp": now - timedelta(days=age)}
        )
    )
    from bson import ObjectId

    repo.collection.update_one(
        {"_id": ObjectId(event.id)},
        {
            "$set": {
                "received_at": now - timedelta(days=age),
                "processed_at": now - timedelta(days=age),
                "processing_status": status,
            }
        },
    )
    return event


def test_retention_preview_preserves_data_and_apply_protects_evidence(mongo_repository, payload):
    settings, repo = mongo_repository
    removable = old_event(repo, payload)
    protected = old_event(repo, payload)
    pending = old_event(repo, payload, status="pending")
    recent = old_event(repo, payload, age=1)
    closed_evidence = old_event(repo, payload)
    old = datetime.now(UTC) - timedelta(days=200)
    repo.alerts.collection.insert_one(
        {
            "status": "open",
            "created_at": old,
            "related_event_ids": [protected.id],
            "dedup_key": "open",
        }
    )
    repo.alerts.collection.insert_one(
        {
            "status": "resolved",
            "created_at": old,
            "updated_at": old,
            "revision": 0,
            "related_event_ids": [closed_evidence.id],
            "dedup_key": "closed",
        }
    )
    preview = retain(repo, settings)
    assert preview["eligible_alerts_in_batch"] == 1 and preview["eligible_events_in_batch"] == 2
    assert preview["deleted_events"] == 0 and repo.collection.count_documents({}) == 5
    result = retain(repo, settings, apply=True)
    assert result["deleted_events"] == 2 and result["deleted_alerts"] == 1
    assert repo.get(removable.id) is None and repo.get(closed_evidence.id) is None
    assert all(repo.get(event.id) for event in (protected, pending, recent))


def test_retention_bounds_and_recent_investigation_are_preserved(mongo_repository, payload):
    settings, repo = mongo_repository
    events = [old_event(repo, payload) for _ in range(4)]
    repo.alerts.collection.insert_one(
        {
            "status": "resolved",
            "created_at": datetime.now(UTC) - timedelta(days=200),
            "updated_at": datetime.now(UTC),
            "related_event_ids": [events[0].id],
            "dedup_key": "recent-edit",
        }
    )
    result = retain(repo, settings, batch_size=1, apply=True)
    assert result["deleted_events"] == 1 and result["deleted_alerts"] == 0
    assert repo.get(events[0].id)
    with pytest.raises(ValueError):
        retain(repo, settings, event_days=1)


def test_host_backfill_does_not_mark_historical_hosts_online_or_overwrite_new_metadata(
    mongo_repository, payload
):
    _, repo = mongo_repository
    old_event(repo, payload, age=10)
    old_event(repo, payload, age=20)
    assert backfill_hosts(repo) == 1
    host = repo.endpoints.hosts.find_one({"_id": payload["endpoint_id"]})
    assert host["last_seen_at"] < datetime.now(UTC) - timedelta(days=9)
    assert host["first_seen_at"] < datetime.now(UTC) - timedelta(days=19)
    repo.endpoints.observe(
        payload["endpoint_id"], "$literal-hostname", "windows", event_received=datetime.now(UTC)
    )
    backfill_hosts(repo)
    assert (
        repo.endpoints.hosts.find_one({"_id": payload["endpoint_id"]})["hostname"]
        == "$literal-hostname"
    )
