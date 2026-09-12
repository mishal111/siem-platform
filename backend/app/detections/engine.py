from datetime import timedelta

from app.config import Settings
from app.detections.rules import (
    ACCOUNT_CREATED,
    FAILED_LOGINS,
    GROUP_FIELDS,
    LOG_CLEARING,
    POWERSHELL,
    PRIVILEGED_GROUP,
    SUCCESS_AFTER_FAILURES,
    Rule,
)
from app.detections.single_event import matching_rule
from app.repository import EventRepository


class DetectionEngine:
    def __init__(self, repository: EventRepository, settings: Settings):
        self.repository = repository
        self.settings = settings

    def eligibility(self) -> dict:
        # Eligibility is fixed relative to server receipt time, not worker execution time.
        return {
            "$expr": {
                "$and": [
                    {
                        "$gte": [
                            "$timestamp",
                            {
                                "$subtract": [
                                    "$received_at",
                                    self.settings.detection_max_lateness_seconds * 1000,
                                ]
                            },
                        ]
                    },
                    {
                        "$lte": [
                            "$timestamp",
                            {
                                "$add": [
                                    "$received_at",
                                    self.settings.detection_future_skew_seconds * 1000,
                                ]
                            },
                        ]
                    },
                ]
            }
        }

    def skip_reason(self, event: dict) -> str | None:
        age = (event["received_at"] - event["timestamp"]).total_seconds()
        if age > self.settings.detection_max_lateness_seconds:
            return "event_too_late"
        if age < -self.settings.detection_future_skew_seconds:
            return "event_clock_ahead"
        if matching_rule(event, ACCOUNT_CREATED, PRIVILEGED_GROUP, POWERSHELL):
            return None
        if (
            event["os"] == "windows"
            and event["event_type"] == "security_log_cleared"
            and event.get("event_code") == 1102
            and event["source"] == "Security"
        ):
            return None
        if event["event_type"] not in ("login_failure", "login_success"):
            return "no_matching_rule"
        username = (event.get("username") or "").strip()
        if (
            not username
            or username.lower() in ("<private>", "unknown", "(null)", "-")
            or not event.get("source_ip")
        ):
            return "missing_authentication_context"
        return None

    def group(self, event: dict) -> dict:
        return {key: event.get(key) for key in GROUP_FIELDS}

    def failures(self, anchor: dict, rule: Rule) -> list[dict]:
        upper = "$lt" if rule == SUCCESS_AFTER_FAILURES else "$lte"
        query = {
            **self.group(anchor),
            **self.eligibility(),
            "event_type": "login_failure",
            "timestamp": {
                "$gte": anchor["timestamp"] - timedelta(seconds=rule.window_seconds),
                upper: anchor["timestamp"],
            },
        }
        if rule == FAILED_LOGINS:
            query["$or"] = [
                {"timestamp": {"$lt": anchor["timestamp"]}},
                {"timestamp": anchor["timestamp"], "_id": {"$lte": anchor["_id"]}},
            ]
        # A bounded witness set proves the threshold without embedding an unbounded episode.
        rows = list(
            self.repository.collection.find(query, {"raw_event": 0, "message": 0})
            .sort([("timestamp", -1), ("_id", -1)])
            .limit(rule.threshold)
            .max_time_ms(3000)
        )
        return list(reversed(rows))

    def emit(self, anchor: dict, evidence: list[dict], rule: Rule) -> None:
        ids = [str(event["_id"]) for event in evidence]
        identity = [rule.rule_id, rule.version]
        if rule == FAILED_LOGINS:
            # Rolling detection windows, with fixed UTC buckets used only for alert suppression.
            identity += [
                self.group(anchor),
                int(anchor["timestamp"].timestamp()) // rule.suppression_seconds,
            ]
        else:
            identity += [str(anchor["_id"])]
        self.repository.alerts.insert_once(
            identity,
            {
                "rule_id": rule.rule_id,
                "rule_version": rule.version,
                "rule_name": rule.name,
                "severity": rule.severity,
                "description": rule.description,
                "endpoint_id": anchor["endpoint_id"],
                "hostname": anchor["hostname"],
                "os": anchor["os"],
                "username": anchor.get("username"),
                "user_domain": anchor.get("user_domain"),
                "source_ip": anchor.get("source_ip"),
                "mitre_technique": rule.mitre_technique,
                "mitre_name": rule.mitre_name,
                "related_event_ids": ids,
                "trigger_event_id": str(anchor["_id"]),
                "event_count": len(ids),
                "failure_count": sum(event["event_type"] == "login_failure" for event in evidence),
                "first_seen": min(event["timestamp"] for event in evidence),
                "last_seen": max(event["timestamp"] for event in evidence),
            },
        )

    def evaluate_anchor(self, anchor: dict, rule: Rule) -> None:
        failures = self.failures(anchor, rule)
        if len(failures) == rule.threshold:
            evidence = failures + ([anchor] if rule == SUCCESS_AFTER_FAILURES else [])
            self.emit(anchor, evidence, rule)

    def evaluate(self, event: dict, renew=lambda: None) -> str | None:
        reason = self.skip_reason(event)
        if reason:
            return reason
        single = matching_rule(event, ACCOUNT_CREATED, PRIVILEGED_GROUP, POWERSHELL)
        if single:
            self.emit(event, [event], single)
            return None
        if event["event_type"] == "security_log_cleared":
            self.emit(event, [event], LOG_CLEARING)
            return None
        if event["event_type"] == "login_success":
            self.evaluate_anchor(event, SUCCESS_AFTER_FAILURES)
            return None
        # A newly received failure may affect already-processed later failures or successes.
        for rule, event_type in (
            (FAILED_LOGINS, "login_failure"),
            (SUCCESS_AFTER_FAILURES, "login_success"),
        ):
            lower = "$gt" if rule == SUCCESS_AFTER_FAILURES else "$gte"
            query = {
                **self.group(event),
                **self.eligibility(),
                "event_type": event_type,
                "timestamp": {
                    lower: event["timestamp"],
                    "$lte": event["timestamp"] + timedelta(seconds=rule.window_seconds),
                },
            }
            # Stream all matching anchors in small batches; do not silently truncate busy groups.
            with (
                self.repository.collection.find(query, {"raw_event": 0, "message": 0})
                .sort([("timestamp", 1), ("_id", 1)])
                .batch_size(100)
                .max_time_ms(3000) as anchors
            ):
                for anchor in anchors:
                    renew()
                    self.evaluate_anchor(anchor, rule)
        return None
