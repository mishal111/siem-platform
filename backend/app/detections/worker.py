import argparse
import json
import logging
import signal
import threading
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from pymongo import ReturnDocument
from pymongo.errors import PyMongoError

from app.config import Settings
from app.detections.engine import DetectionEngine
from app.repository import EventRepository

logger = logging.getLogger("siem.detection")


class LeaseLost(Exception):
    pass


class DetectionWorker:
    def __init__(self, repository: EventRepository, settings: Settings):
        self.repository = repository
        self.settings = settings
        self.engine = DetectionEngine(repository, settings)
        self.state = repository.collection.database.detection_state

    def heartbeat(self, error_type: str | None = None) -> None:
        self.state.update_one(
            {"_id": "worker"},
            {
                "$set": {
                    "last_seen_at": datetime.now(UTC),
                    "last_error_type": error_type,
                }
            },
            upsert=True,
        )

    def claim(self) -> dict | None:
        now = datetime.now(UTC)
        return self.repository.collection.find_one_and_update(
            {
                "$or": [
                    {
                        "processing_status": "pending",
                        "$or": [
                            {"detection_next_attempt": {"$exists": False}},
                            {"detection_next_attempt": {"$lte": now}},
                        ],
                    },
                    {"processing_status": "processing", "processing_lease_until": {"$lte": now}},
                ]
            },
            {
                "$set": {
                    "processing_status": "processing",
                    "processing_token": uuid4().hex,
                    "processing_lease_until": now
                    + timedelta(seconds=self.settings.detection_lease_seconds),
                },
                "$inc": {"processing_attempts": 1},
            },
            sort=[("received_at", 1), ("_id", 1)],
            return_document=ReturnDocument.AFTER,
        )

    def selector(self, event: dict) -> dict:
        return {
            "_id": event["_id"],
            "processing_status": "processing",
            "processing_token": event["processing_token"],
        }

    def renew(self, event: dict) -> None:
        now = datetime.now(UTC)
        if (
            event["processing_lease_until"] - now
        ).total_seconds() > self.settings.detection_lease_seconds / 2:
            return
        until = now + timedelta(seconds=self.settings.detection_lease_seconds)
        result = self.repository.collection.update_one(
            self.selector(event), {"$set": {"processing_lease_until": until}}
        )
        if not result.matched_count:
            raise LeaseLost
        event["processing_lease_until"] = until
        self.heartbeat()

    def finish(self, event: dict, reason: str | None) -> None:
        self.repository.collection.update_one(
            self.selector(event),
            {
                "$set": {
                    "processing_status": "skipped" if reason else "processed",
                    "detection_skip_reason": reason,
                    "processed_at": datetime.now(UTC),
                    "detection_version": 2,
                },
                "$unset": {
                    "processing_token": "",
                    "processing_lease_until": "",
                    "detection_next_attempt": "",
                    "detection_error_type": "",
                },
            },
        )

    def fail(self, event: dict, error: Exception) -> None:
        terminal = event["processing_attempts"] >= self.settings.detection_max_attempts
        self.repository.collection.update_one(
            self.selector(event),
            {
                "$set": {
                    "processing_status": "failed" if terminal else "pending",
                    "detection_error_type": type(error).__name__,
                    "detection_next_attempt": datetime.now(UTC)
                    + timedelta(seconds=min(60, 2 ** min(event["processing_attempts"], 6))),
                },
                "$unset": {"processing_token": "", "processing_lease_until": ""},
            },
        )
        logger.error(
            json.dumps(
                {
                    "event": "detection_failed",
                    "error_type": type(error).__name__,
                    "terminal": terminal,
                }
            )
        )
        self.heartbeat(type(error).__name__)

    def process_one(self) -> bool:
        self.heartbeat()
        event = self.claim()
        if event is None:
            return False
        try:
            if event["processing_attempts"] > self.settings.detection_max_attempts:
                raise RuntimeError("Repeatedly expired detection lease")
            reason = self.engine.evaluate(event, renew=lambda: self.renew(event))
            self.finish(event, reason)
            logger.info(
                json.dumps({"event": "detection_processed", "outcome": reason or "evaluated"})
            )
        except LeaseLost:
            logger.warning('{"event":"detection_lease_lost"}')
        except Exception as exc:
            # Alert writes are idempotent; any completed writes survive a failed/retried job.
            # Never log exception messages because database errors may contain credentials/data.
            self.fail(event, exc)
        return True


def main() -> int:
    parser = argparse.ArgumentParser(description="Persistent SIEM detection worker")
    parser.add_argument(
        "--once", action="store_true", help="Drain currently available jobs then exit"
    )
    parser.add_argument("--health-check", action="store_true", help="Check recent worker heartbeat")
    parser.add_argument(
        "--retry-failed", action="store_true", help="Explicitly requeue failed jobs"
    )
    args = parser.parse_args()
    settings = Settings()
    logging.basicConfig(level=settings.log_level, format="%(message)s")
    repository = EventRepository(settings)
    stopped = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stopped.set())
    try:
        if args.health_check:
            return 0 if repository.detection_status()["worker_recent"] else 1
        repository.initialize()
        if args.retry_failed:
            result = repository.collection.update_many(
                {"processing_status": "failed"},
                {
                    "$set": {"processing_status": "pending", "processing_attempts": 0},
                    "$unset": {"detection_next_attempt": "", "detection_error_type": ""},
                },
            )
            logger.info(
                json.dumps({"event": "failed_jobs_requeued", "count": result.modified_count})
            )
        worker = DetectionWorker(repository, settings)
        while not stopped.is_set():
            try:
                if not worker.process_one():
                    if args.once:
                        state = repository.detection_status()["events"]
                        return (
                            2 if state["pending"] or state["processing"] or state["failed"] else 0
                        )
                    stopped.wait(settings.detection_poll_seconds)
            except PyMongoError:
                logger.error('{"event":"detection_database_unavailable"}')
                if args.once:
                    return 2
                stopped.wait(3)
        return 0
    except PyMongoError:
        logger.error('{"event":"detection_database_unavailable"}')
        return 1
    finally:
        repository.close()


if __name__ == "__main__":
    raise SystemExit(main())
