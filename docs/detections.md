# Detection engine — six rules

The `worker` service evaluates durably stored events independently of ingestion.
It creates alerts with rule versions, MITRE mappings, and retrievable evidence.
These alerts identify sequences worth investigating, not confirmed compromises.

## Run and demonstrate

```bash
docker compose up --build -d --wait backend worker
python3 scripts/detection_demo.py
```

The demo submits **ten synthetic Windows events**: five failed logins, one
success, Security audit-log clearing, account creation, a privileged-group addition,
and a PowerShell indicator. It waits for exactly six
alerts and retrieves each alert's evidence. It does not generate login attempts,
clear real logs, or execute any security activity on your endpoints.

It prints a run ID and replay command. Replay loads the exact same event UIDs,
timestamps, and payloads from `.local/detection-demo/<run-id>.json`. All ten
submissions should then be reported as duplicates, with the same six alert IDs.
Fixtures contain only synthetic data; credentials are read privately from `.env`.
Create a new run if old fixture timestamps fall outside the eligibility policy.

## Rules and evidence

| Rule | Match | Severity | Evidence |
| --- | --- | --- | --- |
| `AUTH-BRUTE-001` | At least 5 matching failures in an inclusive rolling 300-second window | High | 5 distinct failed events proving the threshold |
| `AUTH-SUCCESS-001` | Success preceded by at least 5 matching failures in `[success−600s, success)` | High | 5 failures plus the success |
| `WIN-LOG-CLEAR-001` | `os=windows`, `source=Security`, `event_type=security_log_cleared`, `event_code=1102` | Critical | The Windows clearing event |
| `WIN-ACCOUNT-001` | Windows Security account creation, event 4720 | Medium | The account creation event, including actor and target |
| `WIN-GROUP-001` | Windows Security group addition, event 4728/4732/4756, to an allowlisted privileged SID | High | The group-addition event, actor, group, and member |
| `WIN-PS-001` | Windows Security process creation, event 4688, with a PowerShell executable and qualifying command pattern | High | Process path, command line, and actor from the source event |

Account creation is an activity that warrants review; legitimate administration
also triggers it. The group rule uses SIDs rather than localized group names:
built-in Administrators and Account/Server/Print/Backup Operators (544, 548–551),
plus domain SIDs ending in RID 512, 518, or 519. Ordinary groups and removal events
do not match. The collector supports local, global, and universal additions.

PowerShell matching requires the executable basename to be PowerShell or pwsh.
It checks valid UTF-16LE Base64 following `-EncodedCommand`, `-enc`, or `-ec`, or
combines expression execution (`IEX`/`Invoke-Expression`) with a download operation.
It never executes a command or decoded script. Simple literal strings/comments,
ordinary PowerShell commands, and downloads alone do not match. This is a bounded
heuristic, not a PowerShell interpreter; other encodings, obfuscations, and execution
mechanisms may be missed, and legitimate encoded automation can alert.

Mappings: [account creation T1136](https://attack.mitre.org/techniques/T1136/),
[group additions T1098.007](https://attack.mitre.org/techniques/T1098/007/), and
[PowerShell T1059.001](https://attack.mitre.org/techniques/T1059/001/).

The two authentication rules group by **all** of `endpoint_id`, `os`, `source`,
`username`, `user_domain`, and `source_ip`. Text matches are exact and
case-sensitive. Optional domain values must match, including null. A usable
username and source IP are required; missing/redacted context is skipped instead
of grouping all unknown users or addresses. This conservative first version does
not detect password spraying across accounts, distributed attacks, or local sudo
failures with no source IP. Native macOS SSH/sudo coverage remains as documented
in [macOS telemetry coverage](macos-telemetry.md).

Authentication rules are now **version 2**. SID remains evidence rather than a
grouping key: native Windows 4625 can have unknown SID `S-1-0-0`, while 4624 resolves
the same account's SID. This permits that sequence to correlate. Account name reuse
within a window can combine different SIDs and requires analyst review. Existing
alerts and completed jobs are not rewritten; version 1 alerts remain valid historical
records. See [Windows coverage and validation](windows-collector.md).

Failures at the exact same timestamp as a success are not considered to precede
it. Failure-only windows use `(timestamp, database ID)` to order tied timestamps.
Distinct stored event identities are counted once; collector retries are not
additional failed attempts. Aggregate native failure messages remain one event.

Both authentication rules map to [MITRE ATT&CK T1110](https://attack.mitre.org/techniques/T1110/).
Log clearing maps to [T1070.001](https://attack.mitre.org/techniques/T1070/001/).
Mappings are embedded locally in each alert; processing does not query MITRE.

## Alert identity and suppression

Repeated-failure detection uses a **rolling** five-minute window. Separately, its
alerts are suppressed to one per rule version, matching group, and fixed five-minute
UTC bucket containing the qualifying failure. Windows can cross bucket boundaries
without missing the threshold. A long burst can produce an alert in each bucket;
this is not session-based suppression or one incident per attack.

Success-after-failures and the four single-event rules generate at most one alert
per rule version and triggering stored event. Separate successful logins may each
warrant an alert.

MongoDB enforces a unique full SHA-256 alert key. Detection upserts only populate new alerts;
reprocessing does not overwrite existing evidence, creation time, or analyst edits. The first
valid witness snapshot is retained, so different arrival orders may select different
valid evidence. `event_count` describes the stored witness set (5, 6, or 1), not the
total size of an ongoing attack. `trigger_event_id` is part of that witness set.

## Late events, clocks, and restart recovery

Eligibility is relative to each event's **server-assigned `received_at`**. By default,
source time may be up to 24 hours older or 120 seconds ahead. Older/future events
remain stored and searchable but are marked `skipped` for detection with an explicit
reason. A worker starting days later can still process events that were eligible
when received; worker downtime does not age them out of correlation.

When a failure arrives, the engine reevaluates later stored failures within five
minutes and successes within ten minutes for the same group. This handles failures
arriving after the success was processed, as long as the events meet the receipt-time
policy. Correlation reads include eligible pending and previously processed events,
so results do not depend on a particular worker claim order.

Every event starts `pending`. An atomic database claim changes it to `processing`,
adds a unique lease token, and increments its attempt count. Leases default to 60
seconds and renew during long evaluations. Another worker can reclaim expired work;
an old token cannot acknowledge the new owner's job. Alerts are written before the
event is marked `processed`, so a crash in between can safely repeat evaluation.
This provides at-least-once processing with idempotent alert creation, not a
cross-collection transaction or a claim of exactly-once execution.

Non-applicable events become `skipped`. Errors return jobs to `pending` with a
bounded backoff; after five attempts they remain `failed` for inspection. Database
outages preserve durable state; the worker reconnects/retries. No event or alert
is deleted by the worker. Source retention, database durability, and backups remain
separate operational concerns.

## APIs

All endpoints below require the analyst `X-API-Key`; collector credentials cannot
read them. They are available in the running `/docs` API reference.

| Endpoint | Response |
| --- | --- |
| `GET /api/v1/alerts` | `items`, `next_cursor`; bounded cursor pagination |
| `GET /api/v1/alerts/{id}` | Alert metadata and related event IDs |
| `GET /api/v1/alerts/{id}/events` | Supporting `items` plus `missing_event_ids` |
| `GET /api/v1/detections/rules` | Rule thresholds, windows, grouping, requirements, versions |
| `GET /api/v1/detections/status` | Event processing counts and recent worker heartbeat |

Alert filters: `endpoint_id`, `hostname`, `rule_id`, `severity`, `status`
(`open`, `investigating`, `resolved`, `false_positive`), `assigned_to`,
`mitre_technique`, `start_time`, `end_time`, `limit`, and `cursor`.
Time filters and sorting use **alert creation time**, not source event time. Source
time is shown in `first_seen` and `last_seen`. Limits are 1–200 (default 50); preserve
filters when passing `next_cursor` back. No snapshot isolation is claimed across pages.

Evidence retrieval reports missing IDs explicitly if supporting events were removed
externally. User identity, analyst notes, assignment/status changes, and dashboard
APIs are implemented; see [backend API](backend-api.md). Detection evidence remains
immutable while analyst workflow fields use explicit revisions and audit history.

## Operations and limits

```bash
docker compose logs --tail 50 worker
docker compose stop worker
# With the service stopped, process currently available jobs once:
docker compose run --rm worker python -m app.detections.worker --once
# Explicitly retry failed jobs after resolving their underlying cause:
docker compose run --rm worker python -m app.detections.worker --retry-failed --once
docker compose up -d worker
```

`--once` does not wait indefinitely for scheduled retries or unexpired leases; exit
code 2 means pending/processing/failed work remains. A stopped worker's heartbeat
ages out after 90 seconds. Database readiness of the API is separate from detection
worker health; ingestion can continue while the worker is stopped.

Compose exposes `DETECTION_POLL_SECONDS` (default 1), `DETECTION_MAX_LATENESS_SECONDS`
(86400), and `DETECTION_FUTURE_SKEW_SECONDS` (120). Worker environment settings also
support `DETECTION_LEASE_SECONDS` (60) and `DETECTION_MAX_ATTEMPTS` (5). Changing rule
code or eligibility policy does not automatically reprocess historical completed
events; controlled rule migrations/replay are future work.

The worker streams anchor queries in bounded batches and limits each supporting
failure query to five records. Very large matching groups can still be expensive
because each eligible anchor is evaluated; this is a small-lab implementation,
with no high-throughput claim. Database queries have time limits and failed-job
visibility. Future scaling should be driven by measured ingestion and correlation load.
