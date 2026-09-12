# Backend 1.0 completion — 2026-09-12

Scope agreed before frontend development:

- [x] Six detections, including account creation, privileged-group additions, and PowerShell.
- [x] Analyst/admin/viewer accounts, password hashing, expiring revocable sessions, login throttling.
- [x] Endpoint-specific keys, rotation/revocation, host inventory and heartbeat API.
- [x] Alert status, assignment, notes, and attributable history with concurrent-edit protection.
- [x] Dashboard summaries, trends, and host details using bounded queries.
- [x] Opt-in retention, backup/restore procedures, and a tested local TLS deployment configuration.
- [x] Integration tests, updated API documentation, and a working local administrator account.

Windows VM testing remains deferred. Production DNS, public deployment, and a
frontend are outside this implementation pass. Existing telemetry must be preserved.

## Verified locally

| Check | Result |
| --- | --- |
| Backend suite, including real MongoDB integration | 175 passed; two dependency deprecation warnings |
| Portable collector suite | 57 passed; one native Windows-only test skipped |
| Ruff lint and formatting | Passed across 71 Python files |
| Host operations scripts | Parse under Python 3.9 |
| Development live acceptance | 10 synthetic events, 6 alerts, complete evidence; replay preserved alert IDs |
| HTTPS live acceptance | Same full workflow, with certificate verification enabled |
| Investigation and identity acceptance | Role restrictions, assignment, notes, stale revisions, history, key rotation/revocation passed |
| TLS/proxy checks | HTTP 308 redirects to port 8443; verified certificate; ready; public schema disabled |
| MongoDB isolation | Anonymous reads and application reads of other databases denied |
| Backup verification | Both databases restored into isolated temporary databases; retained collection counts matched |
| Historical host migration | Existing event timestamps preserved; no telemetry deleted |
| Frontend contract | Version 1.0 OpenAPI exported with 27 paths |

Live reports: [development](../.local/backend-smoke-result.json),
[HTTPS](../.local/hardened-smoke-result.json), and
[deployment controls](../.local/deployment-probe-result.json).
Reports and synthetic demo fixtures remain local and contain no credentials.
Test users are deactivated and test endpoint keys revoked. Temporary integration
and restore databases are removed; existing application telemetry is retained.
Retention deletion was tested only against isolated fixtures, not application data.

GitHub Actions now includes backend/collector checks and an isolated HTTPS
acceptance/backup job. The workflow is configured; no remote CI run is claimed.
The Windows collector transfer ZIP was regenerated with all 14 supported event codes.

## Frontend handoff

- Development API: `http://127.0.0.1:8000`; Swagger: `/docs`.
- Initial administrator credentials: `.local/admin-credentials.json`, owner-only.
- [API integration guide](backend-api.md) and [OpenAPI schema](openapi.json).
- [Deployment, backups, retention, and remaining limits](backend-operations.md).

Build login, dashboard, event search, alert investigation, and host pages against
these APIs. The heartbeat endpoint is implemented and tested, but periodic native
collector heartbeat sending remains separate collector work. Last-seen telemetry
does not prove whether a quiet endpoint is online. Native Windows VM validation,
SSO/MFA, high availability, measured capacity, and public hosting remain deferred.
