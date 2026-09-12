# macOS telemetry coverage

## Observed environment

Validated on the development Mac running macOS **26.6.1**, using system Python
**3.9.6**. `/usr/bin/log show` supports `--style ndjson`, explicit start/end times,
and UTC output. Its final JSON summary object is ignored as metadata.

An initial five-minute probe of selected security processes observed authorization,
login-window, security daemon, and Gatekeeper records. Some messages contained
`<private>` markers. The final collector predicate is narrower: `authd`, SSH/sudo,
and selected security-tool messages. The first live collection pass delivered
**67 real macOS events** to the local API with zero pending or rejected payloads.
These are security telemetry, not proof of malicious activity.

The fixture values in `collectors/tests/fixtures.py` are invented. Their field
layout matches observed Unified Log output; no captured personal log messages are
committed to the project.

## Detection inputs

| Activity | Current behavior | Verification |
| --- | --- | --- |
| Authorization daemon (`authd`) | Preserve as informational `security_tool_event`; do not infer a successful login | Native collection/delivery verified |
| SSH failed/accepted password, public-key, or keyboard-interactive messages | Anchored patterns → `login_failure` / `login_success`, user and IP when visible | Synthetic parser fixtures; no live SSH activity observed in probe |
| sudo command audit message | `sudo_execution`, actor, target account, recorded command | Synthetic parser fixtures; native sudo coverage unverified |
| sudo authentication failure message | `login_failure`; an aggregate native message remains one event | Synthetic parser fixtures; native sudo coverage unverified |
| Selected Gatekeeper/XProtect messages | Preserve matching messages as informational security-tool context | Parser fixtures; no malicious scenario generated |
| All shell/process execution and parent-child ancestry | Not collected by this implementation | Requires a suitable process-event source |
| Account creation, admin group changes, firewall activity | Not implemented by this parser | No claimed coverage |

A process name plus a keyword is not sufficient evidence of an attack. Gatekeeper
messages may contain words such as “malware” in benign diagnostics; these are not
promoted to high-severity alerts. MITRE mapping and detection logic come later.
The collector never executes a command contained in an event.

## Operational limits

Unified Logging is a diagnostic log source, not a complete audit trail of every
security operation. Privacy redaction, source logging configuration, permissions,
OS changes, and log retention affect visibility. Missing account/IP data stays
null. The numeric OS logging user ID is not treated as the authenticating username.

The five-second overlap handles ordinary rereads, not arbitrary delayed writes.
Events written after their read window has passed beyond the overlap can be missed.
After an outage the reader resumes from its saved position, but it cannot restore
records already evicted from the OS datastore or events the OS never logged.
Queue saturation or an oversized/invalid source window pauses checkpoint progress
with an explicit error; this requires operator attention before OS retention expires.

The first release runs in the foreground. LaunchAgent packaging, central heartbeats,
per-endpoint credentials, and Windows collection remain later work. It does not
change privacy settings or claim comprehensive endpoint detection coverage.

Apple documents a separate [Endpoint Security API](https://developer.apple.com/documentation/endpointsecurity)
for system events such as process execution. That is a potential future source;
it has not been integrated into this Python collector. Command options were checked
against the installed `log help show` output on this Mac.
