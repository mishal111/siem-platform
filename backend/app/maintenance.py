"""Bounded, opt-in offline retention. No event/alert TTL is installed automatically."""

import argparse
import json
from datetime import UTC, datetime, timedelta

from pymongo.errors import PyMongoError

from app.config import Settings
from app.repository import EventRepository


def retain(
    repository, settings, event_days=30, alert_days=180, batch_size=500, apply=False, now=None
):
    if not 1 <= batch_size <= 1000 or not 1 <= event_days <= alert_days <= 3650:
        raise ValueError("Invalid retention ranges or batch size")
    if event_days * 86400 <= settings.detection_max_lateness_seconds + 600:
        raise ValueError(
            "Event retention must exceed detection lateness plus its correlation window"
        )
    now = now or datetime.now(UTC)
    event_cutoff = now - timedelta(days=event_days)
    alert_cutoff = now - timedelta(days=alert_days)
    closed = {
        "status": {"$in": ["resolved", "false_positive"]},
        "created_at": {"$lt": alert_cutoff},
        "$or": [{"updated_at": {"$lt": alert_cutoff}}, {"updated_at": {"$exists": False}}],
    }
    candidates = list(
        repository.alerts.collection.find(closed, {"revision": 1})
        .sort("_id", 1)
        .limit(batch_size)
        .max_time_ms(3000)
    )
    removed_alerts = 0
    if apply:
        for row in candidates:
            selector = {
                **closed,
                "_id": row["_id"],
                "revision": row.get("revision", {"$exists": False}),
            }
            removed_alerts += repository.alerts.collection.delete_one(selector).deleted_count
    omitted_alert_ids = [row["_id"] for row in candidates] if not apply else []
    old_events = {
        "received_at": {"$lt": event_cutoff},
        "processed_at": {"$lt": event_cutoff},
        "processing_status": {"$in": ["processed", "skipped"]},
    }
    pipeline = [
        {"$match": old_events},
        {"$sort": {"received_at": 1, "_id": 1}},
        {"$set": {"_event_identity": {"$toString": "$_id"}}},
        {
            "$lookup": {
                "from": "alerts",
                "localField": "_event_identity",
                "foreignField": "related_event_ids",
                "pipeline": [
                    {"$match": {"_id": {"$nin": omitted_alert_ids}}},
                    {"$limit": 1},
                    {"$project": {"_id": 1}},
                ],
                "as": "_references",
            }
        },
        {"$match": {"_references": {"$size": 0}}},
        {"$limit": batch_size},
        {"$project": {"_id": 1}},
    ]
    events = list(repository.collection.aggregate(pipeline, maxTimeMS=5000, allowDiskUse=True))
    removed_events = (
        repository.collection.delete_many(
            {**old_events, "_id": {"$in": [row["_id"] for row in events]}}
        ).deleted_count
        if apply and events
        else 0
    )
    return {
        "mode": "apply" if apply else "dry_run",
        "event_days": event_days,
        "alert_days": alert_days,
        "batch_limit": batch_size,
        "eligible_alerts_in_batch": len(candidates),
        "eligible_events_in_batch": len(events),
        "deleted_alerts": removed_alerts,
        "deleted_events": removed_events,
    }


def backfill_hosts(repository):
    rows = repository.collection.aggregate(
        [
            {"$sort": {"endpoint_id": 1, "received_at": -1}},
            {
                "$group": {
                    "_id": "$endpoint_id",
                    "hostname": {"$first": "$hostname"},
                    "os": {"$first": "$os"},
                    "received_at": {"$first": "$received_at"},
                    "first_received_at": {"$min": "$received_at"},
                }
            },
        ],
        maxTimeMS=5000,
        allowDiskUse=True,
    )
    count = 0
    for row in rows:
        repository.endpoints.observe(
            row["_id"],
            row["hostname"],
            row["os"],
            event_received=row["received_at"],
            observed_at=row["received_at"],
            first_observed_at=row["first_received_at"],
        )
        count += 1
    return count


def main():
    parser = argparse.ArgumentParser(description="Preview or apply bounded offline retention")
    parser.add_argument("--event-days", type=int, default=30)
    parser.add_argument("--alert-days", type=int, default=180)
    parser.add_argument("--batch-size", type=int, default=500)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument(
        "--offline-confirmed",
        action="store_true",
        help="Confirm API and detection workers are stopped before deleting data",
    )
    parser.add_argument(
        "--backfill-hosts",
        action="store_true",
        help="Populate host metadata from existing events; deletes nothing",
    )
    args = parser.parse_args()
    if args.apply and not args.offline_confirmed:
        parser.error(
            "Stop API/worker writers and back up the database; then use --offline-confirmed"
        )
    if args.backfill_hosts and args.apply:
        parser.error("Run backfill and retention separately")
    settings = Settings()
    repository = EventRepository(settings)
    try:
        repository.initialize()
        result = (
            {"backfilled_hosts": backfill_hosts(repository)}
            if args.backfill_hosts
            else retain(
                repository, settings, args.event_days, args.alert_days, args.batch_size, args.apply
            )
        )
        print(json.dumps(result))
        return 0
    except ValueError as exc:
        print(str(exc))
        return 1
    except PyMongoError:
        print("Maintenance failed; inspect database availability and retry the bounded operation")
        return 1
    finally:
        repository.close()


if __name__ == "__main__":
    raise SystemExit(main())
