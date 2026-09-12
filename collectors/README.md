# Endpoint collectors

The macOS collector runs directly on the host with **Python 3.9+ and no third-party
packages**. It reads selected Unified Log records, normalizes them, persists them
to a local SQLite queue, and sends them to the authenticated SIEM API.
The Windows collector reads the native Security channel using **Python 3.9+ and
pywin32**. See [Windows setup and validation](../docs/windows-collector.md) for VM
transfer, log permissions, auditing, secure connectivity, and bookmark recovery.
The commands below automatically choose the host OS; the macOS-specific details
apply only to the Unified Log reader.

## Run from the project root

Start the backend with `docker compose up -d backend`, then:

```bash
# One catch-up pass, then exit. First run looks back 60 seconds by default.
python3 -m collectors.main --once

# Collect in the foreground until Ctrl-C.
python3 -m collectors.main

# Or run for a bounded period. In-flight reads/delivery may finish after the duration.
python3 -m collectors.main --duration 60

# Inspect local counters while the collector is stopped.
python3 -m collectors.main --status

# Attempt delivery of queued events, without reading native logs.
python3 -m collectors.main --drain
```

Run the collector from a normal terminal. macOS blocks `/usr/bin/log` inside some
sandboxes; when run through this coding environment it requires sandbox approval.
The collector does not request sudo, alter logging privacy settings, enable SSH,
or install a background service. Log availability depends on the current user's
permissions and macOS version.

It reads the collector key from the project's `.env`, regardless of working
directory. An alternative `--env-file path` accepts simple `KEY=VALUE` entries
(not shell commands or variable expansion). Environment variables take precedence.
The analyst key is not used by the collector.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `SIEM_API_URL` | `http://127.0.0.1:8000/api/v1/events` | Single-event endpoint |
| `SIEM_API_KEY` | Fallback to `COLLECTOR_API_KEY` | Ingestion credential |
| `COLLECTOR_STATE_DIR` | `.local/collector` under project root | Durable state directory |
| `COLLECTOR_POLL_SECONDS` | `5` | Pause between reads when caught up |
| `COLLECTOR_REQUEST_TIMEOUT` | `5` | Per-request timeout in seconds |
| `COLLECTOR_BATCH_SIZE` | `20` | Maximum sequential sends per delivery cycle |
| `COLLECTOR_LOOKBACK_SECONDS` | `60` | Initial lookback only; existing checkpoint takes precedence |
| `COLLECTOR_MAX_EVENTS` | `10000` | Combined pending/rejected payload count limit |
| `COLLECTOR_MAX_BYTES` | `16777216` | Combined serialized pending/rejected payload byte limit |

The backend still exposes single-event ingestion. A delivery batch is a group of
individual HTTP requests, not a bulk API call. Remote URLs require HTTPS with
normal certificate validation. Redirects and environment HTTP proxies are disabled
to prevent accidental credential forwarding.

## Reliability and status

- macOS source reads cover at most 30 seconds, overlap by 5 seconds, and lag wall time
  by 3 seconds to allow ordinary log persistence delay. Catch-up windows run until
  current time. Each query is limited to 20 seconds and 8 MiB of output.
- Windows source reads scan at most 100 records per batch with 8 MiB of rendered
  XML and 256 KiB per event. Bookmarks and selected payloads commit together. A
  missing/reused bookmarked record reports a source gap and requires explicit
  recovery; see the Windows guide before using `--reset-windows-bookmark`.
- Each native event receives a deterministic UUID derived from the endpoint ID,
  native metadata, timestamp, and visible message. Queued payloads remain unchanged
  across retries. Recent sent IDs prevent overlapping reads from requeuing events.
- SQLite commits queued events and their source checkpoint in the same transaction.
  The initial read position is also persisted before the first query. A full queue
  or malformed selected record retains the checkpoint and reports an error.
- A valid 201/200 receipt with the matching event UID and endpoint ID is required
  before removing a queued payload. Receipts retain no raw payload. They are kept
  for up to 48 hours, capped at 20,000; the backend remains the final duplicate guard.
- Network errors, 408/425/429, and 5xx preserve the queue and schedule bounded
  exponential backoff with jitter. Retry state survives a process restart.
- 400/409/413/415/422 move the event to `rejected`, retaining its payload and HTTP
  reason locally. It is not retried automatically and does not block later events.
  Inspect and resolve rejected records before the queue reaches its capacity.
- Credential errors, redirects, wrong endpoint URLs, and unexpected statuses stop
  delivery with an explicit error; queued events remain intact.
- Only one process may own a state directory. Do not delete or share that directory:
  it holds the endpoint identity, unsent data, and read position.

`--status` shows pending/rejected counts, buffered bytes, cumulative deliveries,
checkpoint, last capture/delivery time, and the next retry time. Runtime logs report
the same counters without event messages or credentials. This is **local collector
health**; a central host heartbeat endpoint is still a later milestone.

Exit codes: `0` completed with an empty healthy queue; `1` configuration, access,
or delivery blocker; `2` capture errors or remaining pending/rejected events.
`--drain` respects the retry timer and may exit with pending work rather than waiting.

On macOS, the state directory is mode 0700 and the SQLite file is mode 0600.
Windows requires NTFS ACLs as shown in the setup guide. Payload bytes
are bounded; SQLite pages, WAL, indexes, and recent receipt metadata add overhead.
The queue is not encrypted independently of the host filesystem.

## Coverage and tests

See [macOS telemetry coverage](../docs/macos-telemetry.md) for what was verified
on the development Mac and what remains fixture-only.

```bash
python3 -m unittest discover -s collectors/tests -v
docker compose --profile test run --rm tests
docker compose --profile test run --rm --no-deps tests ruff check --no-cache /workspace/collectors
```

The first suite covers parsing, durable state, overlap, capacity, retries,
acknowledgment validation, and credential failures without reading private logs.
Backend tests also validate collector fixtures against the actual Pydantic schema.
