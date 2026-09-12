# Backend API and frontend integration

Backend version 1.0 provides event search, six detections, user sessions, endpoint
enrollment, alert investigations, host inventory, and dashboard summaries. All
application routes below start with `/api/v1`. Development OpenAPI is available at
`/openapi.json` and Swagger at `/docs`; a saved schema is in [openapi.json](openapi.json).

## Local administrator and login

```bash
docker compose up --build -d --wait backend worker
python3 scripts/bootstrap_admin.py
```

The bootstrap script creates `admin` with a random password and writes its initial
credentials to `.local/admin-credentials.json` with mode 0600. It does not print the
password or overwrite an existing credentials file. Read that file in a local
editor. If setup was interrupted, use the hidden-prompt CLI below to recover; an
existing credentials file alone does not prove the account was created. After a
password change, the initial file no longer contains the current password.

For manually creating another account with local server access:

```bash
docker compose exec backend python -m app.admin my-admin --role admin
```

The CLI prompts without echoing the password. There is no public administrator
bootstrap or self-registration endpoint.

`POST /auth/login` accepts JSON `username` and `password`. A successful response
contains `access_token`, `token_type=bearer`, `expires_at`, and `user`. Send
`Authorization: Bearer <access_token>` for subsequent user requests. Swagger calls
this security scheme **HTTPBearer**. `GET /auth/me` returns the current user;
`POST /auth/logout` revokes the current session and returns 204.

Passwords are 12–128 characters and stored using salted scrypt (`N=131072, r=8,
p=1`). Password hashing is limited to two concurrent operations per process.
Session tokens contain 256 bits of randomness; only SHA-256 token hashes are
stored. Sessions expire after eight hours by default. Expiry is checked on every
request independently of MongoDB TTL cleanup. User deactivation, role changes,
and password changes invalidate all existing sessions for that user.

The frontend should keep the bearer token in memory, send it only to the configured
API, and return to login on 401. The API does not set authentication cookies, and
does not provide refresh tokens. A later SSO/MFA integration can replace this local
account flow. Passwords, session tokens, and full collector keys must not appear in
application logs, URLs, or screenshots.

## Roles and development compatibility

| Capability | Viewer | Analyst | Admin | Collector |
| --- | --- | --- | --- | --- |
| Read events, alerts, evidence, hosts, dashboard | Yes | Yes | Yes | No |
| Read assignment directory | Yes | Yes | Yes | No |
| Update alert status, assignment, notes | No | Yes | Yes | No |
| Manage users and endpoint keys | No | No | Yes | No |
| Ingest events / submit heartbeat | No | No | No | Own enrolled endpoint |

Development retains the old `X-API-Key` credentials when `ALLOW_LEGACY_KEYS=true`.
The analyst development key permits reads only; it cannot edit investigations or
manage accounts. The collector development key can ingest across endpoints for
existing collectors and demos. Set `ALLOW_LEGACY_KEYS=false` after migrating those
collectors. Hardened deployment requires this setting to be false.

An invalid Bearer header never falls back to a valid development API key.
Endpoint keys cannot be used as analyst sessions, and analyst sessions do not grant
event-ingestion rights. Permission checks are enforced by the backend.

## User and endpoint management

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/users` | Admin creates `username`, `password`, and `role` |
| GET | `/users` | Admin lists public user records; `limit`, `after` cursor |
| GET | `/users/directory` | Logged-in users list active analysts/admins for assignments |
| PATCH | `/users/{id}` | Admin changes role, active state, or password with `expected_revision` |
| GET | `/users/{id}/history` | Admin reads attributable account changes |
| POST | `/auth/password` | Logged-in user supplies `current_password` and `new_password` |
| POST | `/endpoints` | Admin enrolls endpoint UUID, hostname, and OS; returns key once |
| GET | `/endpoints` | Admin lists registrations without full keys/hashes |
| PATCH | `/endpoints/{id}` | Admin sets `active` with `expected_revision` |
| POST | `/endpoints/{id}/rotate-key` | Admin rotates key with `expected_revision` |
| GET | `/endpoints/{id}/history` | Admin reads enrollment, rotation, and revocation history |
| POST | `/endpoints/heartbeat` | Collector reports its queue and source status |

List endpoints are bounded to 1–100 results. `next_cursor` is passed back as
`after`; it is a UUID for users/endpoints and a literal endpoint ID for hosts.
Passwords and stored key hashes are omitted from public user and endpoint records.
API keys are returned only on enrollment/rotation and cannot be recovered later.
Rotation invalidates the previous key. A revoked registration rejects both ingestion
and heartbeat requests. Already admitted in-flight requests may finish.

Enroll the **existing UUID from the collector's `--status` output**; do not replace
its state directory. Put the returned key in that collector's `SIEM_API_KEY` setting.
The backend requires its event/heartbeat endpoint ID and OS to match the enrollment.
Hostname changes are display metadata; the UUID remains the identity.

Heartbeat JSON contains `endpoint_id`, `hostname`, `os`, `collector_version`,
`pending`, `rejected`, and optional `source_error`. The backend assigns the receipt
time. Native collectors currently update inventory through event ingestion; their
periodic heartbeat sender is not wired in yet. A null `last_heartbeat_at` therefore
means **no heartbeat received**, not a proven unhealthy host.

User and endpoint histories are capped at 500 entries per record. Mutations fail
explicitly when full rather than discarding audit history. Existing administrators
cannot be demoted or deactivated through the API; this prevents administrator
lockout under concurrent edits. Such changes require controlled offline database
administration. There is no anonymous password recovery endpoint; a local server
administrator can provision a recovery admin and reset a user's password.

## Alert investigations

| Method | Path | Behavior |
| --- | --- | --- |
| PATCH | `/alerts/{id}` | Change `status` and/or `assigned_to` with `expected_revision` |
| POST | `/alerts/{id}/notes` | Append `text` with client-generated UUID `note_id` and `expected_revision` |
| GET | `/alerts/{id}/notes` | Retrieve up to 100 retained notes |
| GET | `/alerts/{id}/history` | Page changes using `after_revision` and `limit` (1–100) |

Statuses are `open`, `investigating`, `resolved`, and `false_positive`. Reopening is
supported. Assignments must name an active analyst or admin; send
`assigned_to: null` to unassign. Alert filters now support `status` and `assigned_to`.

Example edit after reading an alert at revision 0:

```json
{"expected_revision": 0, "status": "investigating"}
```

Successful edits increment `revision`. Competing edits using the same revision
cannot both succeed: the stale one returns **409**, and the frontend must reload
before submitting an intentional new edit. Existing alerts without a revision
start at 0 and migrate on their first edit.

Notes contain plain text up to 4,000 characters. Render them as text in React.
Retrying the same note UUID, actor, and text does not append it twice; different
content with the same UUID is a conflict. Concurrent note submissions can return
409 and should be retried after reloading. Notes and the corresponding audit entry
commit atomically within the alert document. Each alert supports up to 100 notes
and 500 changes; reaching a bound returns an explicit conflict.

History records the actor ID, server time, action, revision, and changed fields.
Detection evidence, rule identity, severity, timestamps, and related event IDs
remain immutable. Repeated detection evaluation does not reopen or overwrite an
investigated alert. Existing evidence retrieval still reports missing event IDs if
records were removed outside the supported retention workflow.

## Dashboard and hosts

`GET /dashboard/summary?hours=24` accepts 1–168 hours and returns:

- `start_time`, `end_time`, `as_of`, and an explicit `time_basis`.
- Event/alert totals and distributions by event type, OS, severity, status, and rule.
- Ten top endpoint IDs and source IPs, plus UTC hourly event counts with empty bins filled.
- `recently_reporting_hosts`: hosts with ingestion/heartbeat contact within five minutes.

Event charts use **server receipt time**; alert charts use **alert creation time**.
The event explorer continues to filter by native source timestamp. The first and
last hourly bins can be partial. Queries have server-side time limits and do not
claim a cross-collection snapshot while ingestion continues.

`GET /hosts` lists observed host metadata with bounded cursor pagination.
`GET /hosts/{endpoint_id}` returns metadata, retained lifetime event/alert counts,
and ten recent events and alerts. A quiet host's old last-seen time does not prove
it is offline. Registration and observed inventory are separate: an enrolled host
with no telemetry appears in `/endpoints`, and appears in `/hosts` once it reports.

To populate inventory from historical data without making old hosts appear online:

```bash
docker compose exec -T backend python -m app.maintenance --backfill-hosts
```

## Errors and browser configuration

Errors use `{"detail": ...}`. Common statuses: 401 invalid/expired credentials;
403 insufficient role or wrong endpoint; 409 duplicate identity/stale revision;
422 invalid fields; 429 throttled; 503 database/capacity unavailable. Honor
`Retry-After`. The API returns `X-Request-ID` and `Cache-Control: no-store`; request
logs exclude bodies, headers, query values, and raw database exceptions.

For a separate Vite development origin, set this in `.env` and recreate the API:

```env
CORS_ORIGINS=["http://localhost:5173"]
```

Only exact configured origins are accepted; Authorization and PATCH are supported.
Wildcard origins and embedded URL credentials are rejected. For deployment, see
[operations and HTTPS](backend-operations.md).

## Verification

```bash
docker compose --profile test run --rm tests
python3 scripts/backend_smoke.py
```

The acceptance script creates clearly labeled synthetic telemetry, verifies all
six alerts and their evidence, exercises login/roles, tests notes/assignments and
stale edits, then checks endpoint-key rotation and revocation. Its test accounts
are deactivated and its test endpoint revoked afterward; synthetic events/alerts
remain as reviewable evidence. The administrator password is read privately from
the initial credentials file; no credential is included in the result report.

Password storage follows the [OWASP scrypt guidance](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).
