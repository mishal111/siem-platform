# Event contract, schema version 1

The backend accepts normalized events. Native Windows/macOS parsing belongs in
collectors; the backend validates that contract and canonicalizes UTC timestamps.

## Identity and storage

- `endpoint_id`: a stable installation identity persisted by the collector.
  A hostname is display metadata and may change. At this milestone, endpoint identity
  is asserted by the sender, not cryptographically bound to its credential.
- `event_uid`: a UUID assigned **once** before the collector queues an event.
  Retries must reuse it. A unique MongoDB index covers `(endpoint_id, event_uid)`.
- `event_code`: the native Windows event code (for example `4625`), or `null`.
- `source_record_id`: an optional native log record identifier, represented as a string.
- `id`: the server's MongoDB record ID, returned in responses and used in detail URLs.
- `schema_version`: currently `1`; unknown top-level fields are rejected.

Identical canonical payloads using the same identity return HTTP 200 and
`duplicate: true`. First insertion returns 201. A different canonical payload
using the same identity returns 409 and leaves the stored event unchanged.
Optional omitted fields and explicit defaults normalize identically; raw-event
array order and raw-event values remain significant. Changed collector versions
or messages require a new event identity, not a retry under the old identity.

## Time

`timestamp` is the source event time and must include a timezone. It is converted
to UTC and truncated to milliseconds before hashing and storage, matching BSON
datetime precision. `received_at` is assigned by the server. Clients cannot set it.
Historical and future source timestamps are accepted in this milestone; they are
untrusted data, not proof of when an activity actually occurred. Detection eligibility
allows 24 hours of lateness and 120 seconds of future skew relative to receipt time
by default; out-of-range events remain stored. See [detection behavior](detections.md).

## Required input

`event_uid`, `endpoint_id`, `timestamp`, `hostname`, `os`, `source`, `event_type`,
and `message` are required. `os` is `windows` or `macos`. The event-type vocabulary
and all optional fields are listed in the running `/docs` schema.

`username` identifies the actor/authenticating account, with `user_domain` and
`user_sid` where available. For account/group changes, `target_username` and
`target_user_sid` identify the affected account; `group_name` and `group_sid`
identify the affected group. Process context includes process IDs, names,
parent-process fields, and command line. Missing data is `null`, not invented.

`severity` defaults to `info` and describes the event. Future rule-generated alert
severity is a separate decision; a collector's severity is not a detection result.

`raw_event` preserves selected JSON evidence. Bodies are limited to 1 MiB by default,
including chunked requests; compressed bodies are rejected. Raw data must have
finite numbers, signed 64-bit integers, no null bytes in field names, and nesting
of at most 32 levels. Encode larger numeric identifiers as strings. Collectors
must avoid collecting secrets unnecessarily; no automatic credential redaction
is claimed for stored telemetry.

## Search and pagination

Exact-match filters: `endpoint_id`, `hostname`, `os`, `event_type`, `event_code`,
`username`, `source_ip`, `severity`. Text filters are case-sensitive literals;
they are not regular expressions or MongoDB query objects.

`start_time` and `end_time` apply inclusive bounds to source event time and require
timezones. Results sort by `(timestamp DESC, id DESC)`. `limit` defaults to 50 and
must be between 1 and 200. Pass `next_cursor` back as `cursor`, retaining the same
filters, until it is `null`. A cursor is an opaque position, not an authentication
token. Pages are not a snapshot: concurrent arrivals with old timestamps may
appear later; refresh from the first page to see newly arrived recent events.

## Durability and errors

MongoDB writes request `w=majority` and journaling before acknowledgment. The local
database is a standalone instance, so this does not provide replication or high
availability. Every new event has internal `processing_status=pending`. The separate
detection worker claims events, writes any uniquely keyed alerts, and then marks
them processed/skipped. Failures are retried and eventually flagged for inspection.
Processing metadata is internal and does not change ingestion response payloads.

On a transient database error the API returns 503 with `Retry-After: 3`. A write
may have succeeded before its acknowledgment was lost, so resend the **same**
event UID and payload. Repeated delivery will not create another event.

Validation errors return 422 without reflecting the rejected payload. Oversized
bodies return 413, malformed JSON 400, unsupported content encoding 415, and
missing/wrong API credentials 401. Never retry an unchanged 4xx payload indefinitely.
