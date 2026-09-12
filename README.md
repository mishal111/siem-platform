# Cross-Platform SIEM

A portfolio SIEM for collecting and investigating Windows and macOS security events.
**Current milestone: backend 1.0 and the first React analyst workspace, with login, a live dashboard, event search, investigations, and host views.**
Windows native collection is implemented with portable tests; live VM validation is
deferred until a Windows VM is available. Development can continue without it.
See the [frontend guide](frontend/README.md) for implemented views and remaining UI work.
The [frontend completion report](docs/frontend-completion.md) records the local test results.

## Open the analyst workspace

```bash
docker compose --profile frontend up --build -d --wait frontend worker
```

Open **http://127.0.0.1:5173** and sign in with the account saved in
`.local/admin-credentials.json`. For a new setup, first complete the local setup
steps below. The frontend uses your backend's data; refreshing the browser requires
sign-in again because sessions are kept only in memory.

## Start locally

Prerequisites: Docker Desktop with Docker Compose, and Python 3.9+ for the
standard-library setup/demo scripts. The backend itself runs Python 3.12 in Docker;
you do not need to upgrade macOS's system Python.

From the repository root:

```bash
python3 scripts/init_env.py
docker compose up --build -d --wait backend worker
python3 scripts/bootstrap_admin.py
docker compose ps
python3 scripts/smoke_test.py
```

The setup script creates a gitignored `.env` with two random keys and owner-only
permissions. It never prints secrets or overwrites an existing file. Placeholder
keys from `.env.example` are intentionally rejected by the backend.

- API reference: <http://127.0.0.1:8000/docs>
- Liveness: <http://127.0.0.1:8000/api/v1/health>
- Database readiness: <http://127.0.0.1:8000/api/v1/health/ready>

The smoke script stores one clearly labeled synthetic event per run, retries it,
reads it back, searches events, and verifies collector/analyst separation. It
loads credentials privately from `.env`.

The administrator's initial credentials are saved in `.local/admin-credentials.json`
with mode 0600. Use `POST /api/v1/auth/login` in Swagger and then authorize with the
returned Bearer token. See [backend API and frontend integration](docs/backend-api.md)
for role permissions, endpoint enrollment, alert edits, and dashboard responses.

To collect selected real security telemetry from the Mac, run this on the host:

```bash
python3 -m collectors.main --once
python3 -m collectors.main --status
```

Run `python3 -m collectors.main` for foreground collection until Ctrl-C. No extra
Python packages or background service are required. The collector buffers events
in `.local/collector`, reuses their identities on retries, and resumes its source
checkpoint after restart. See [collector setup](collectors/README.md) and the
[verified telemetry coverage](docs/macos-telemetry.md).

For the Windows VM, use the [Windows setup and validation guide](docs/windows-collector.md).
Run `python3 scripts/package_windows_collector.py` to create a collector-only transfer
ZIP without server credentials or endpoint state. The Windows reader requires
pywin32, Security-log access, and an HTTPS endpoint or an existing SSH tunnel to
the Mac's loopback API.

To test automatic alerts using synthetic events:

```bash
python3 scripts/detection_demo.py
```

This creates five failed logins, a subsequent success, log clearing, account creation,
a privileged-group addition, and a PowerShell indicator. The worker should produce
**six alerts** with retrievable evidence. The
script prints a replay command that checks the same events don't create duplicate
alerts. It performs no real login attempts or log clearing. See [detection rules
and operation](docs/detections.md).

For the complete login → endpoint enrollment → ingestion → six alerts →
investigation → key revocation acceptance test:

```bash
python3 scripts/backend_smoke.py
```

```bash
docker compose logs --tail 50 backend
docker compose stop
```

The named `mongo_data` volume preserves events across container restarts. The
default API port is bound to localhost and MongoDB is not published to the host.
This is the local development configuration. A separate, locally tested HTTPS stack
with authenticated MongoDB is provided in `deploy/compose.yml`; see
[operations, backups, and retention](docs/backend-operations.md).

## Implemented API

| Method | Endpoint | Credential | Behavior |
| --- | --- | --- | --- |
| GET | `/api/v1/health` | None | API liveness |
| GET | `/api/v1/health/ready` | None | MongoDB connectivity |
| POST | `/api/v1/events` | Collector key | Validate and persist one event |
| GET | `/api/v1/events` | Analyst key | Filtered, paginated event search |
| GET | `/api/v1/events/{record_id}` | Analyst key | Retrieve one stored event |
| GET | `/api/v1/alerts` | Analyst key | Filter and page through generated alerts |
| GET | `/api/v1/alerts/{record_id}` | Analyst key | Alert details and evidence IDs |
| GET | `/api/v1/alerts/{record_id}/events` | Analyst key | Retrieve supporting events |
| GET | `/api/v1/detections/rules` | Analyst key | Rule definitions and thresholds |
| GET | `/api/v1/detections/status` | Analyst key or user session | Worker heartbeat and job counts |
| POST | `/api/v1/auth/login` | Username/password | Expiring user session |
| GET / POST | `/api/v1/users` | Admin session | User administration |
| POST | `/api/v1/endpoints` | Admin session | Enroll endpoint and issue scoped key |
| PATCH | `/api/v1/alerts/{record_id}` | Analyst/admin session | Status, assignment, concurrent-edit protection |
| GET / POST | `/api/v1/alerts/{record_id}/notes` | Read role / analyst session | Investigation notes |
| GET | `/api/v1/alerts/{record_id}/history` | Read role | Attributable change history |
| GET | `/api/v1/dashboard/summary` | Read role | Bounded summaries and hourly trends |
| GET | `/api/v1/hosts` | Read role | Observed host inventory |

Both credentials use the `X-API-Key` header. In Swagger's **Authorize** dialog,
`CollectorKey` is for ingestion and `AnalystKey` is for searches and event details.
Use the respective values from your local `.env`. These are development access
keys retained for compatibility. User sessions and per-endpoint credentials are
implemented; hardened deployment disables development keys. User sessions can also
read all event, alert, and detection endpoints shown above. The complete route and
permission reference is in [backend API](docs/backend-api.md).

Example event:

```json
{
  "schema_version": 1,
  "event_uid": "2384d2a0-2da1-4b97-aec7-8cf179a8fb80",
  "endpoint_id": "windows-lab-01",
  "timestamp": "2026-09-10T07:00:00Z",
  "hostname": "WIN11-LAB",
  "os": "windows",
  "source": "Security",
  "event_type": "login_failure",
  "event_code": 4625,
  "username": "administrator",
  "source_ip": "192.0.2.20",
  "severity": "medium",
  "message": "Synthetic failed login"
}
```

First ingestion returns **201** with `{ "event": {...}, "duplicate": false }`.
Retrying an identical event returns **200**, the original stored record, and
`duplicate: true`. Reusing its endpoint/UID with changed data returns **409**.
`received_at` and the database `id` are assigned by the backend.

Search accepts `endpoint_id`, `hostname`, `os`, `event_type`, `event_code`,
`username`, `source_ip`, `severity`, `start_time`, `end_time`, `limit`, and `cursor`.
For example: `/api/v1/events?event_type=login_failure&limit=20`.
The response contains `items` and `next_cursor`; there is no unbounded result mode.

See [the complete event contract](docs/event-contract.md) for identity, timezone,
pagination, payload limits, raw-data constraints, and retry semantics.

## Run tests and lint

```bash
docker compose --profile test run --build --rm tests
docker compose --profile test run --rm --no-deps tests ruff check --no-cache .
docker compose --profile test run --rm --no-deps tests ruff format --check --no-cache .
python3 -m unittest discover -s collectors/tests -v
```

The first command starts MongoDB if needed and runs API tests plus **real MongoDB
integration tests**. Each integration test gets a uniquely named `siem_test_*`
database, which is removed afterward. Tests do not remove the application database.
Integration coverage includes concurrent duplicate submissions, persistent reads
after app restart, exact-match filters, and pagination with tied timestamps.

The test service mounts `backend/`, so source edits are visible without rebuilding.
Rebuild it when dependencies change. Test-only dependencies are excluded from the
runtime Docker image.

## Optional host Python development

Requires a separately installed Python 3.12+; do not use system Python 3.9 for the API.

```bash
python3.12 -m venv .venv
.venv/bin/pip install -r backend/requirements-dev.txt
docker compose -f docker-compose.yml -f docker-compose.local.yml up -d mongodb
.venv/bin/uvicorn app.main:create_app --factory --app-dir backend --reload --no-access-log
```

Run from the repository root so settings find `.env`. The optional Compose override
publishes MongoDB on `127.0.0.1:27017`. Stop the containerized backend first if it
already occupies port 8000.

```bash
.venv/bin/pytest backend/tests
TEST_MONGO_URI=mongodb://127.0.0.1:27017 .venv/bin/pytest backend/tests
```

Without `TEST_MONGO_URI`, real database tests are explicitly skipped. The Docker
test command sets this variable and runs the full suite.

## Project layout

```text
backend/app/       API, users, endpoint keys, workflows, dashboard, retention, detections
backend/tests/     API, validation, middleware, and MongoDB integration tests
collectors/        Windows/macOS readers, parsers, durable queue, sender, and tests
frontend/          React analyst workspace, browser tests, production container
scripts/           Admin setup, acceptance tests, collector package, backup/restore verification
deploy/            Separate HTTPS deployment with authenticated MongoDB
docs/              Event contract, architecture, and remaining milestones
```

See [architecture and scope](docs/architecture.md) for current limitations and the
remaining implementation sequence.
