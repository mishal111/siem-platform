# Backend operations and deployment

## Existing development stack

`docker compose up --build -d --wait backend worker` runs the API on
`http://127.0.0.1:8000`. The development database remains on its existing named
volume. It is isolated by the Compose network and does not require MongoDB
credentials. This configuration is for local development.

## Separate HTTPS deployment

The deployment configuration uses a **different Compose project and database
volume**. It does not migrate or replace development telemetry.

```bash
python3 scripts/init_deployment.py
docker compose -f deploy/compose.yml up --build -d --wait
python3 scripts/bootstrap_admin.py --deployment
docker compose -f deploy/compose.yml cp caddy:/data/caddy/pki/authorities/local/root.crt .local/deployment-ca.crt
python3 scripts/backend_smoke.py --deployment
```

The default URL is `https://localhost:8443`. Caddy issues a local certificate, and
the acceptance script verifies it against the copied **public** root certificate.
It does not disable certificate verification or install a CA in the host trust
store. The initial administrator credentials are in
`.local/deployment-admin-credentials.json`, mode 0600. Development keys do not work
in this stack. Public Swagger/OpenAPI routes are disabled in hardened mode.

Implemented controls:

- Caddy 2.11.4 terminates TLS, redirects local HTTP port 8080 to HTTPS port 8443,
  limits bodies and connection timeouts, and sets security headers.
- Only Caddy's ports are published, and they bind to loopback by default.
  MongoDB is on an internal network and is not published.
- MongoDB authentication is enabled. The application has `readWrite` access to
  only the `siem` database; root credentials are not mounted into the API/worker.
- API and worker run as a non-root user with read-only filesystems, bounded tmpfs,
  dropped capabilities, no-new-privileges, and memory/process limits.
- Caddy drops capabilities except the bind capability required by its image.
  Its readiness probe uses an unpublished loopback listener and checks backend readiness.
- The API enforces explicit Host names, HTTPS for application routes, exact CORS
  origins, per-peer request limits, concurrent-request limits, and body-read deadlines.
- Login throttles persist in MongoDB across application restarts, separately by
  normalized username and transport peer. Expired throttles/sessions have TTL indexes.

The proxy's address is fixed at `172.30.53.2`; the API trusts forwarded headers only
from that address. Backend address `172.30.53.3` is reserved separately. If this
subnet conflicts with an existing network, update the subnet, both addresses, and
the Uvicorn trusted-proxy setting together. Headers supplied directly by an
untrusted client do not establish its identity or HTTPS status.

The general request limit is a bounded in-process limiter, not a global distributed
quota. Deploy one API process with this configuration; an internet deployment may
need an edge gateway/WAF and traffic-specific limits. Defaults: 6,000 requests per
peer per minute, 100 concurrent requests, and 10 seconds to receive a body. Login
defaults are 10 attempts per username and 30 per peer per minute. Counters use fixed
windows, so bursts can straddle a boundary. MongoDB queries also have time limits.

Deployment secrets live in `.local/deployment-secrets`, mode 0700. Files are 0444
inside that owner-only directory because Compose file secrets are bind mounts and
the non-root application must read its explicitly mounted file. The API/worker
receive only `mongo_uri`; backup/root tools are mounted only into MongoDB. Protect
and back up that directory separately. Re-running initialization preserves existing
passwords; editing secret files does not rotate credentials in an existing MongoDB
volume. Rotation requires a coordinated database user-password change.

For a future public domain, provide `SIEM_DOMAIN`, `SIEM_BIND`, `SIEM_HTTPS_PORT`,
`SIEM_HTTP_PORT`, and exact HTTPS `CORS_ORIGINS` through a deployment env file. For
example, a public installation would normally use ports 443 and 80 with a domain
pointing to the deployment host. **No public DNS or public deployment was performed
for this milestone.** Check firewall access, certificate issuance, backups,
dependency/image updates, and capacity on the actual host before rollout.

## Backups and restore verification

```bash
# Existing development database:
python3 scripts/backup_database.py --verify-restore
# Separate authenticated deployment database:
python3 scripts/backup_database.py --deployment --verify-restore
```

The script briefly stops the API and worker, creates a compressed archive in
`.local/backups` with mode 0600, and restarts whichever writers were running. Stop
any external writers too. Verification restores into a uniquely named
`siem_restorecheck_*` database, compares retained collection counts, and removes only
that temporary database. It never restores over the application database.

TTL-managed sessions and login throttle counts are excluded from count comparison
because they can expire during restore. Verification checks successful restore and
collection counts; it is not a byte-for-byte document comparison or an HA failover
test. A failed run retains its archive for inspection and attempts to restart the
writers. Backups contain telemetry and password/key hashes; keep them private and
encrypted when storing them off-host. Database users and deployment secret files
must be provisioned separately on a replacement server.

For an actual restore, stop writers, initialize an isolated replacement deployment,
and use MongoDB's `mongorestore --archive --gzip` with namespace mapping if needed.
The hardened MongoDB container includes `/run/secrets/mongo_restore_config` for
authorized restore administration without putting credentials in command arguments.
Validate the replacement with the acceptance script before switching traffic.

## Opt-in retention

No automatic event or alert deletion is enabled. Preview a bounded batch:

```bash
docker compose exec -T backend python -m app.maintenance --event-days 30 --alert-days 180
```

To apply after a verified backup, stop all API and worker writers:

```bash
docker compose stop backend worker
docker compose run --rm --no-deps backend python -m app.maintenance --event-days 30 --alert-days 180 --apply --offline-confirmed
docker compose up -d --wait backend worker
```

Use `-f deploy/compose.yml` consistently for the separate deployment. The offline
confirmation is an operator assertion: the CLI cannot discover external writers.

Retention deletes only old resolved/false-positive alerts with no recent edits,
and old processed/skipped events that are not referenced by any retained alert.
Open/investigating alerts, pending/processing/failed jobs, recent events, and retained
evidence are protected. Event receipt and processing times determine event age;
alert creation and last-edit times determine alert age. Event retention must exceed
the configured detection lateness plus its correlation window.

Each run handles at most 500 alerts and 500 events by default, configurable to
1–1,000. Repeat batches during the maintenance window if needed. Deletes across
collections are not one transaction; rerunning safely continues a partial batch.
The supported workflow requires writers to remain stopped throughout application.

Idempotency applies while the original event is retained. Replaying a deleted
event can store it again; usual detection lateness rules still apply. Retention
does not silently delete analyst history independently from its alert. User and
endpoint audit histories are not pruned by this command.

## Remaining deployment limits

This is a tested portfolio backend, not a high-availability service. MongoDB is a
single instance; replication, managed SSO/MFA, independent audit-log export, measured
high-volume capacity, and public-host rollout are separate deployment work. Native
Windows VM validation remains explicitly deferred. These limits do not block the
frontend's events, alerts, investigations, and dashboard work.

Primary references: [Caddy automatic HTTPS](https://caddyserver.com/docs/automatic-https),
[Caddy 2.11.4](https://github.com/caddyserver/caddy/releases/tag/v2.11.4),
[Docker Compose secrets](https://docs.docker.com/compose/how-tos/use-secrets/),
[MongoDB backup](https://www.mongodb.com/docs/database-tools/mongodump/), and
[MongoDB restore](https://www.mongodb.com/docs/database-tools/mongorestore/).
