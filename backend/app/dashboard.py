from datetime import UTC, datetime, timedelta

from fastapi import HTTPException
from pydantic import AwareDatetime, BaseModel

from app.alerts import AlertFilters
from app.models import EventFilters, OperatingSystem


class HostRecord(BaseModel):
    endpoint_id: str
    hostname: str
    os: OperatingSystem
    first_seen_at: AwareDatetime
    last_seen_at: AwareDatetime
    last_event_received_at: AwareDatetime | None = None
    last_heartbeat_at: AwareDatetime | None = None
    collector_version: str | None = None
    pending: int | None = None
    rejected: int | None = None
    source_error: str | None = None


def host_record(row):
    return HostRecord(endpoint_id=row["_id"], **row)


def summary(repository, hours, now=None):
    now = now or datetime.now(UTC)
    start = now - timedelta(hours=hours)

    def grouped(field):
        return [
            {"$group": {"_id": "$" + field, "count": {"$sum": 1}}},
            {"$sort": {"count": -1, "_id": 1}},
        ]

    event_facets = {
        "total": [{"$count": "count"}],
        "by_type": grouped("event_type"),
        "by_os": grouped("os"),
        "top_hosts": grouped("endpoint_id") + [{"$limit": 10}],
        "top_source_ips": [{"$match": {"source_ip": {"$nin": [None, ""]}}}]
        + grouped("source_ip")
        + [{"$limit": 10}],
        "trend": [
            {
                "$group": {
                    "_id": {
                        "$dateToString": {
                            "format": "%Y-%m-%dT%H:00:00Z",
                            "date": "$received_at",
                            "timezone": "UTC",
                        }
                    },
                    "count": {"$sum": 1},
                }
            }
        ],
    }
    events = next(
        repository.collection.aggregate(
            [{"$match": {"received_at": {"$gte": start, "$lte": now}}}, {"$facet": event_facets}],
            maxTimeMS=3000,
            allowDiskUse=True,
        )
    )
    alerts = next(
        repository.alerts.collection.aggregate(
            [
                {"$match": {"created_at": {"$gte": start, "$lte": now}}},
                {
                    "$facet": {
                        "total": [{"$count": "count"}],
                        "by_severity": grouped("severity"),
                        "by_status": grouped("status"),
                        "by_rule": grouped("rule_id"),
                    }
                },
            ],
            maxTimeMS=3000,
            allowDiskUse=True,
        )
    )
    trend_counts = {row["_id"]: row["count"] for row in events["trend"]}
    trend = []
    hour = start.replace(minute=0, second=0, microsecond=0)
    while hour <= now:
        key = hour.strftime("%Y-%m-%dT%H:00:00Z")
        trend.append({"timestamp": hour, "count": trend_counts.get(key, 0)})
        hour += timedelta(hours=1)

    def counts(rows):
        return {row["_id"]: row["count"] for row in rows}

    return {
        "as_of": now,
        "start_time": start,
        "end_time": now,
        "time_basis": "server_received_at_for_events_and_created_at_for_alerts",
        "event_count": events["total"][0]["count"] if events["total"] else 0,
        "alert_count": alerts["total"][0]["count"] if alerts["total"] else 0,
        "events_by_type": counts(events["by_type"]),
        "events_by_os": counts(events["by_os"]),
        "alerts_by_severity": counts(alerts["by_severity"]),
        "alerts_by_status": counts(alerts["by_status"]),
        "alerts_by_rule": counts(alerts["by_rule"]),
        "top_hosts": [
            {"endpoint_id": row["_id"], "count": row["count"]} for row in events["top_hosts"]
        ],
        "top_source_ips": [
            {"source_ip": row["_id"], "count": row["count"]} for row in events["top_source_ips"]
        ],
        "events_per_hour": trend,
        "recently_reporting_hosts": repository.endpoints.hosts.count_documents(
            {"last_seen_at": {"$gte": now - timedelta(minutes=5)}}, maxTimeMS=3000
        ),
    }


def host_detail(repository, endpoint_id):
    row = repository.endpoints.hosts.find_one({"_id": endpoint_id})
    if not row:
        raise HTTPException(404, "Host not found")
    query = {"endpoint_id": endpoint_id}
    return {
        "host": host_record(row),
        "event_count": repository.collection.count_documents(query, maxTimeMS=3000),
        "alert_count": repository.alerts.collection.count_documents(query, maxTimeMS=3000),
        "recent_events": repository.search(EventFilters(endpoint_id=endpoint_id, limit=10)).items,
        "recent_alerts": repository.search_alerts(
            AlertFilters(endpoint_id=endpoint_id, limit=10)
        ).items,
    }
