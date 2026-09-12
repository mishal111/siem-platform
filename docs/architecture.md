# Architecture and milestone status

## Frontend milestone 1 — analyst workspace

```text
Browser → local frontend (React production build, port 5173)
        → same-origin /api proxy → existing FastAPI backend → MongoDB
```

The UI includes login, dashboard summaries, event/alert search, evidence,
investigation edits and notes, audit history, host details, and detection rules.
Bearer tokens live only in tab memory. The development server also proxies `/api`
without exposing server credentials or requiring CORS changes. Viewer controls
are read-only; backend authorization enforces permissions. The frontend container
serves nested routes and sets a same-origin Content Security Policy.

The UI runs in the development Compose project and preserves existing telemetry.
The separate HTTPS stack remains API-only. See the [frontend guide](../frontend/README.md).

## Backend 1.0 — implemented before frontend development

The backend now provides six detection rules; viewer/analyst/admin sessions;
scoped endpoint credentials with rotation/revocation; alert status, assignments,
notes, and atomic audit history; host inventory; and bounded dashboard summaries.
Existing development keys remain compatible and are disabled in hardened mode.

Operational support includes opt-in offline retention that protects retained alert
evidence, historical host backfill, private database backups with isolated restore
verification, and a separate HTTPS/authenticated-MongoDB deployment. The development
and HTTPS acceptance tests exercise all six alerts and investigation workflows.

See [API and frontend integration](backend-api.md), [operations](backend-operations.md),
and [completion status](backend-completion.md). Earlier milestones below describe
how the core event pipeline was built.

## Implemented in milestone 4; live Windows VM validation deferred

```text
Windows Security channel → bounded native Event Log reads → named XML parsing
  → selected normalized events + bookmark/fingerprint (one SQLite transaction)
  → shared sender → authenticated API → MongoDB → detection worker
```

Fourteen Windows event codes are mapped with actor/target distinctions, native
record identity, and explicit gap recovery. Both endpoint collectors enforce one
process per state directory. Authentication rules are version 2 to allow unknown
failed-logon SIDs to correlate with resolved successful-logon SIDs. Portable and
real MongoDB pipeline tests cover the implementation. The Windows CI job has not
been verified here. At the user's request, live Windows validation is deferred
until a VM is available and does not block subsequent development. Native Security
log collection remains unverified; see [Windows setup](windows-collector.md).

## Implemented in milestone 3

```text
MongoDB events (pending)
  → independent worker claims event with an expiring lease
  → rule evaluation / event-time correlation
  → immutable, uniquely keyed alert with evidence IDs
  → event marked processed or skipped

Authenticated analyst API → alerts / supporting events / worker status
```

Three rules cover repeated failures, success after failures, and Windows audit-log
clearing. Failure arrivals also reevaluate relevant later stored events to handle
out-of-order delivery. Rule behavior, bounded lateness, suppression, failure recovery,
and the synthetic demo are documented in [detections](detections.md). The MongoDB
standalone deployment uses atomic event claims and idempotent alert upserts instead
of cross-collection transactions. The worker runs as its own Compose service.

## Implemented in milestone 2

```text
macOS Unified Log (selected processes/messages)
  → bounded NDJSON reads with overlap
  → native parser and stable event identity
  → SQLite queue + checkpoint (one transaction)
  → single-event HTTP sender with persistent backoff
  → existing authenticated API → MongoDB
```

The collector runs on host Python 3.9+ using only the standard library. Its
permissions, queue limits, recovery semantics, and commands are documented in
[collector setup](../collectors/README.md). [Telemetry coverage](macos-telemetry.md)
separates live observations from fixture-only parsing. It runs in the foreground;
no background agent is installed. The backend heartbeat API is now available;
periodic heartbeat sending remains separate collector work.

## Implemented in milestone 1

```text
Synthetic/manual event sender (collector key)
  → FastAPI: byte limit → authentication → event validation
  → MongoDB: unique event identity, acknowledged journaled write
  → HTTP 201 (new) / 200 (identical retry) / 409 (identity conflict)

Analyst API client (separate analyst key)
  → FastAPI: authentication → typed exact-match filters / event ID
  → MongoDB → bounded event page / event detail
```

Sync PyMongo operations run in FastAPI's worker thread pool through synchronous
route functions. Startup index creation runs in a thread via the application
lifespan. Connections are pooled and closed at shutdown. Database startup failure
prevents the app from starting; Compose waits for MongoDB readiness first.
Runtime failures return 503 without exposing database credentials or host details.

`/health` checks API liveness; `/health/ready` additionally pings MongoDB. The backend
container runs as a non-root user, publishes only on host loopback, and uses a
private Compose network to reach MongoDB. The default configuration publishes
no MongoDB port. The optional local-development override binds it to loopback.

## Current limits

- Development keys are optional compatibility credentials. User sessions and
  endpoint-specific keys are available; managed SSO/MFA is separate deployment work.
- The development API binds to loopback. The Windows lab can use an existing SSH
  local port forward. Direct remote collector URLs require HTTPS; a managed TLS
  deployment is now included and locally tested. Public DNS/hosting rollout remains
  outside this local implementation.
- The default development MongoDB remains local and unauthenticated. The separate
  deployment enables MongoDB authentication. Replication and high availability
  are not implemented; backup/restore and retention tooling are included.
- No bulk event endpoint. The React dashboard and analyst investigation views are
  implemented; user/endpoint management screens remain future frontend work.
- No throughput claim. Query indexes support event browsing, job claims, and correlation;
  additional indexes will be selected using measured query plans.
- API body deadlines, rate/concurrency limits, host checks, and proxy timeouts are
  implemented. Distributed traffic quotas and measured production capacity remain
  deployment concerns.

## Subsequent milestones

1. Extend frontend administration, saved searches, and deployment as needed.
2. Add collector heartbeat scheduling if live online/offline status is needed.
3. Measure capacity and adapt deployment controls to the actual hosting environment.

Deferred validation: run the native collector in a Windows VM when one becomes
available. Synthetic tests do not verify Security-log permissions, audit settings,
native reader behavior, or VM connectivity.

## Reference documentation consulted

- [FastAPI application lifespan](https://fastapi.tiangolo.com/advanced/events/)
- [PyMongo connection options](https://www.mongodb.com/docs/languages/python/pymongo-driver/current/connect/connection-options/)
- [Pydantic settings](https://docs.pydantic.dev/latest/concepts/pydantic_settings/)
