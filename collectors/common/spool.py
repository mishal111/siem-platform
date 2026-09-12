import json
import os
import sqlite3
import time
from pathlib import Path
from uuid import uuid4


class QueueFull(Exception):
    pass


class AlreadyRunning(Exception):
    pass


class Spool:
    """Atomic source checkpoints and durable delivery state; one process owns a spool."""

    def __init__(self, directory, max_events=10000, max_bytes=16 * 1024 * 1024):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.directory.chmod(0o700)
        self.max_events = max_events
        self.max_bytes = max_bytes
        self.lock = None
        if os.name == "posix":
            import fcntl

            # Held for the lifetime of this context-managed Spool, closed in close().
            self.lock = open(self.directory / "collector.lock", "a")  # noqa: SIM115
            os.chmod(self.directory / "collector.lock", 0o600)
            try:
                fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                self.lock.close()
                raise AlreadyRunning("Another collector owns this state directory") from None
        elif os.name == "nt":
            import msvcrt

            self.lock = open(self.directory / "collector.lock", "a+b")  # noqa: SIM115
            if self.lock.seek(0, os.SEEK_END) == 0:
                self.lock.write(b"\0")
                self.lock.flush()
            self.lock.seek(0)
            try:
                msvcrt.locking(self.lock.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError:
                self.lock.close()
                raise AlreadyRunning("Another collector owns this state directory") from None
        database = self.directory / "spool.sqlite3"
        descriptor = os.open(database, os.O_CREAT | os.O_RDWR, 0o600)
        os.close(descriptor)
        database.chmod(0o600)
        self.connection = sqlite3.connect(str(database), timeout=5)
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA synchronous=FULL")
        self.connection.executescript("""
            CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS events (
                uid TEXT PRIMARY KEY, payload TEXT, size INTEGER NOT NULL,
                state TEXT NOT NULL, reason TEXT, created_at REAL NOT NULL, updated_at REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS events_state_order ON events(state, created_at);
        """)
        with self.connection:
            self.connection.execute(
                "INSERT OR IGNORE INTO metadata VALUES ('endpoint_id', ?)", (str(uuid4()),)
            )

    def get(self, key, default=None):
        row = self.connection.execute("SELECT value FROM metadata WHERE key=?", (key,)).fetchone()
        return row[0] if row else default

    def _set(self, key, value):
        self.connection.execute(
            "INSERT INTO metadata VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, str(value)),
        )

    def set(self, key, value):
        with self.connection:
            self._set(key, value)

    @property
    def endpoint_id(self):
        return self.get("endpoint_id")

    def enqueue_window(self, events, checkpoint):
        self.enqueue_batch(events, {"checkpoint": checkpoint})

    def enqueue_batch(self, events, metadata):
        """Commit payloads and all source position fields together, or neither."""
        now = time.time()
        unique = {event["event_uid"]: event for event in events}
        with self.connection:
            count, size = self.connection.execute(
                "SELECT COUNT(*), COALESCE(SUM(size),0) FROM events WHERE state != 'sent'"
            ).fetchone()
            for uid, event in unique.items():
                if self.connection.execute("SELECT 1 FROM events WHERE uid=?", (uid,)).fetchone():
                    continue
                payload = json.dumps(event, separators=(",", ":"), sort_keys=True, allow_nan=False)
                event_size = len(payload.encode())
                count += 1
                size += event_size
                if count > self.max_events or size > self.max_bytes:
                    # The context manager rolls back *all* rows and the checkpoint on failure.
                    raise QueueFull("Local queue capacity reached; source checkpoint retained")
                self.connection.execute(
                    "INSERT INTO events VALUES (?, ?, ?, 'pending', NULL, ?, ?)",
                    (uid, payload, event_size, now, now),
                )
            for key, value in metadata.items():
                self._set(key, value)
            self._set("last_capture_at", now)

    def reset_windows_bookmark(self):
        # Explicit recovery retains endpoint identity, queued payloads, and delivery receipts.
        with self.connection:
            self.connection.execute("DELETE FROM metadata WHERE key='windows_position'")
            self._set("windows_start", 0)
            self._set("windows_replay_count", int(self.get("windows_replay_count", "0")) + 1)
            self._set("windows_last_replay_at", time.time())

    def pending(self, limit=20):
        rows = self.connection.execute(
            "SELECT uid, payload FROM events WHERE state='pending' "
            "ORDER BY created_at, rowid LIMIT ?",
            (limit,),
        )
        return [(uid, json.loads(payload)) for uid, payload in rows]

    def acknowledge(self, uid):
        with self.connection:
            self.connection.execute(
                "UPDATE events SET state='sent', payload=NULL, size=0, updated_at=? WHERE uid=?",
                (time.time(), uid),
            )
            self._set("delivered_total", int(self.get("delivered_total", "0")) + 1)
            self._set("last_delivery_at", time.time())
            self._set("retry_count", 0)
            self._set("next_retry_at", 0)

    def quarantine(self, uid, reason):
        with self.connection:
            self.connection.execute(
                "UPDATE events SET state='rejected', reason=?, updated_at=? WHERE uid=?",
                (reason, time.time(), uid),
            )

    def retry_later(self, delay):
        with self.connection:
            self._set("retry_count", int(self.get("retry_count", "0")) + 1)
            self._set("next_retry_at", time.time() + delay)

    def prune_receipts(self):
        # Receipts carry no payload. Keep recent overlap protection with a bounded row count.
        with self.connection:
            self.connection.execute(
                "DELETE FROM events WHERE state='sent' AND updated_at < ?",
                (time.time() - 172800,),
            )
            self.connection.execute("""
                DELETE FROM events WHERE state='sent' AND uid NOT IN (
                    SELECT uid FROM events WHERE state='sent' ORDER BY updated_at DESC LIMIT 20000
                )
            """)

    def status(self):
        counts = dict(self.connection.execute("SELECT state, COUNT(*) FROM events GROUP BY state"))
        return {
            "endpoint_id": self.endpoint_id,
            "pending": counts.get("pending", 0),
            "rejected": counts.get("rejected", 0),
            "recent_receipts": counts.get("sent", 0),
            "buffered_bytes": self.connection.execute(
                "SELECT COALESCE(SUM(size),0) FROM events"
            ).fetchone()[0],
            "delivered_total": int(self.get("delivered_total", "0")),
            "checkpoint": self.get("checkpoint"),
            "last_capture_at": self.get("last_capture_at"),
            "last_delivery_at": self.get("last_delivery_at"),
            "retry_count": int(self.get("retry_count", "0")),
            "next_retry_at": float(self.get("next_retry_at", "0")),
            "windows_bookmark_present": self.get("windows_position") is not None,
            "source_error": self.get("source_error", ""),
            "windows_replay_count": int(self.get("windows_replay_count", "0")),
            "windows_last_replay_at": self.get("windows_last_replay_at"),
        }

    def close(self):
        self.connection.close()
        if self.lock:
            self.lock.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
