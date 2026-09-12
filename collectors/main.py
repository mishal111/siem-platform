import argparse
import json
import logging
import platform
import signal
import socket
import sqlite3
import time

from collectors.common.config import ConfigurationError, load_config
from collectors.common.errors import ParseError, SourceError, SourceGap
from collectors.common.sender import DeliveryBlocked, Sender
from collectors.common.spool import AlreadyRunning, QueueFull, Spool
from collectors.macos.parser import normalize
from collectors.macos.source import MacOSSource
from collectors.windows.parser import normalize as normalize_windows
from collectors.windows.source import WindowsSource

logger = logging.getLogger("siem.collector")


def capture_windows(config, spool, source, once=False, now=None):
    if spool.get("windows_start") is None:
        now = time.time() if now is None else now
        spool.set("windows_start", max(0, now - config.lookback_seconds))
    try:
        position = json.loads(spool.get("windows_position", "{}"))
        if not isinstance(position, dict) or (
            position
            and (
                not isinstance(position.get("bookmark"), str)
                or not isinstance(position.get("fingerprint"), str)
            )
        ):
            raise ValueError
    except (ValueError, TypeError) as exc:
        raise SourceGap("Invalid saved Windows bookmark; inspect local state") from exc
    batch = source.read(
        position, float(spool.get("windows_start")), once=once, limit=min(100, spool.max_events)
    )
    events = []
    for row in batch.rows:
        event = normalize_windows(row, spool.endpoint_id)
        if event is not None:
            events.append(event)
    metadata = {"windows_position": json.dumps(batch.position)} if batch.position else {}
    spool.enqueue_batch(events, metadata)
    logger.info(
        json.dumps(
            {"event": "capture_windows", "source_records": len(batch.rows), "selected": len(events)}
        )
    )
    return batch.has_more


def capture_window(config, spool, source, now=None):
    now = time.time() if now is None else now
    cutoff = int(now) - config.settle_seconds
    if spool.get("checkpoint") is None:
        # Anchor the first window even on failure, so a sliding lookback cannot skip records.
        spool.set("checkpoint", cutoff - config.lookback_seconds)
    checkpoint = float(spool.get("checkpoint"))
    if checkpoint > cutoff:
        logger.warning('{"event":"source_clock_moved_backwards","action":"waiting"}')
        return False
    if checkpoint == cutoff:
        return False
    end = min(cutoff, checkpoint + config.window_seconds)
    rows = source.read(max(0, checkpoint - config.overlap_seconds), end)
    events = []
    for row in rows:
        event = normalize(row, spool.endpoint_id, socket.gethostname())
        if event is not None:
            events.append(event)
    spool.enqueue_window(events, end)
    logger.info(
        json.dumps(
            {"event": "capture_window", "source_records": len(rows), "selected": len(events)}
        )
    )
    return end < cutoff


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Windows/macOS SIEM collector (foreground, Python 3.9+)"
    )
    parser.add_argument("--env-file", help="Development KEY=VALUE file; defaults to project .env")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--once", action="store_true", help="Read up to now and attempt queued delivery"
    )
    mode.add_argument(
        "--drain", action="store_true", help="Send queued events without reading native logs"
    )
    mode.add_argument(
        "--status", action="store_true", help="Print queue status while collector is stopped"
    )
    mode.add_argument(
        "--reset-windows-bookmark",
        action="store_true",
        help="Acknowledge a gap and replay retained Security logs next run; preserve the queue",
    )
    parser.add_argument("--duration", type=float, help="Stop collection after this many seconds")
    args = parser.parse_args(argv)
    if args.duration is not None and args.duration <= 0:
        parser.error("--duration must be positive")
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    try:
        options = {"env_file": args.env_file} if args.env_file else {}
        config = load_config(
            **options, require_key=not (args.status or args.reset_windows_bookmark)
        )
        windows = platform.system() == "Windows"
        if not (args.status or args.drain) and platform.system() not in ("Darwin", "Windows"):
            raise ConfigurationError("Native collection requires Windows or macOS")
        if args.reset_windows_bookmark and not windows:
            raise ConfigurationError("Bookmark recovery must run on the Windows endpoint")
        with Spool(config.state_dir, config.max_events, config.max_bytes) as spool:
            if args.status:
                print(json.dumps(spool.status(), indent=2))
                return 0
            if not args.drain:
                source_os = "windows" if windows else "macos"
                existing_os = spool.get("source_os")
                if existing_os is None and spool.get("checkpoint") is not None:
                    existing_os = "macos"
                if existing_os and existing_os != source_os:
                    raise ConfigurationError("Use a separate state directory on each endpoint")
                spool.set("source_os", source_os)
            if args.reset_windows_bookmark:
                spool.reset_windows_bookmark()
                print(json.dumps({"event": "windows_replay_requested", **spool.status()}))
                return 0
            sender = Sender(config, spool)
            if args.drain:
                while sender.drain():
                    pass
                print(json.dumps(spool.status(), indent=2))
                return 0 if spool.status()["pending"] == spool.status()["rejected"] == 0 else 2
            stopped = False

            def stop(signum, frame):
                nonlocal stopped
                stopped = True

            source = WindowsSource() if windows else MacOSSource()
            original_handlers = {
                sig: signal.signal(sig, stop) for sig in (signal.SIGINT, signal.SIGTERM)
            }
            started = time.monotonic()
            # A fixed cutoff makes --once finite even on a busy host.
            once_cutoff = time.time() if args.once else None
            errors = 0
            try:
                while not stopped:
                    if args.duration and time.monotonic() - started >= args.duration:
                        break
                    sender.drain()
                    catchup = False
                    try:
                        if windows:
                            catchup = capture_windows(config, spool, source, once=args.once)
                        else:
                            catchup = capture_window(config, spool, source, now=once_cutoff)
                        spool.set("source_error", "")
                    except (SourceError, ParseError, QueueFull) as exc:
                        errors += 1
                        spool.set("source_error", type(exc).__name__)
                        logger.error(
                            json.dumps(
                                {
                                    "event": "capture_failed",
                                    "error_type": type(exc).__name__,
                                    "action": "inspect_gap_then_reset_windows_bookmark"
                                    if isinstance(exc, SourceGap)
                                    else "checkpoint_retained",
                                }
                            )
                        )
                        if args.once:
                            break
                        if isinstance(exc, SourceGap):
                            # Require explicit operator recovery instead of silently skipping data.
                            break
                    sender.drain()
                    spool.prune_receipts()
                    logger.info(json.dumps({"event": "collector_status", **spool.status()}))
                    if args.once and not catchup:
                        # Drain already captured events without extending the source window.
                        while sender.drain():
                            pass
                        break
                    if not catchup:
                        until = time.monotonic() + config.poll_seconds
                        while not stopped and time.monotonic() < until:
                            time.sleep(0.1)
            finally:
                for sig, handler in original_handlers.items():
                    signal.signal(sig, handler)
            status = spool.status()
            print(json.dumps({"event": "collector_stopped", **status}))
            return 0 if not errors and status["pending"] == status["rejected"] == 0 else 2
    except (ConfigurationError, DeliveryBlocked, AlreadyRunning) as exc:
        logger.error(json.dumps({"event": "collector_blocked", "reason": str(exc)}))
        return 1
    except (OSError, sqlite3.Error):
        logger.error('{"event":"collector_storage_or_io_failed","action":"inspect_local_state"}')
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
