# Windows collector — setup and validation

The foreground collector reads the local **Security** channel with the modern
Windows Event Log API through `pywin32`. It shares the macOS collector's SQLite
queue, authenticated sender, persistent retries, and receipt checks. Windows
Python 3.9+ is supported by the code; use Python 3.12 for the VM and CI setup below.
No service, scheduled task, audit setting, or firewall change is installed automatically.

## 1. Transfer the collector to your Windows VM

On the development Mac, from the project root:

```bash
python3 scripts/package_windows_collector.py
```

Copy `.local/windows-collector.zip` using your VM's shared folder or existing file
transfer connection. Extract it to a directory belonging to your Windows user,
for example `C:\Users\YOUR_USER\siem`. The ZIP includes source, synthetic tests,
and this guide. It excludes server credentials, the database, and endpoint state.
**Do not copy the Mac's `.env` or `.local/collector` to Windows.** Each endpoint
creates its own UUID and queue on first use.

Open an **elevated PowerShell** in the extracted directory for the lab's Security
log access. These examples use an installed Windows Python 3.12:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r collectors\windows\requirements.txt
.\.venv\Scripts\python.exe -m unittest discover -s collectors\tests -v
Get-WinEvent -LogName Security -MaxEvents 1 |
    Select-Object Id, RecordId, TimeCreated, ProviderName
```

The dependency is Windows-only (`pywin32==312`). The last command must return a
Security event. If access is denied, fix the collection account's log access
before collecting. The Application-log unit smoke test does not prove Security
log permissions. An eventual service account needs a deliberately configured
Security channel ACL; this milestone uses an elevated foreground lab process.

## 2. Connect the VM to the existing backend

On the Mac, keep the backend and detection worker running:

```bash
docker compose up --build -d --wait backend worker
```

The API binds to the Mac's loopback address. `127.0.0.1` inside the VM is the VM
itself. For this lab, an **existing SSH connection from Windows to the Mac** can
forward the API securely. In a separate Windows terminal, substitute the actual
Mac username and reachable IP or your configured SSH alias:

```powershell
ssh -N -o ExitOnForwardFailure=yes -L 127.0.0.1:8000:127.0.0.1:8000 MAC_USER@MAC_IP
```

Leave that terminal open. This requires the Mac's SSH service to have been enabled
and reachable already; the collector does not enable it or open ports. Verify a
new SSH host fingerprint against the Mac before trusting it. If you already have
an HTTPS API deployment instead, use its `/api/v1/events` URL with a trusted
certificate. Remote plaintext HTTP is rejected and TLS verification stays enabled.
Do not change the Compose port binding merely to make the VM connect.

In the collector PowerShell terminal:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/v1/health/ready
Copy-Item collectors\windows\.env.example .env.windows
notepad .env.windows
```

Set `SIEM_API_KEY` to the **collector** key from the Mac's `.env`, using a local
editor. Do not give the VM the analyst key or paste keys into chat. For SSH
forwarding, leave the example API URL unchanged. For HTTPS, edit the URL.
The default initial lookback in this example is five minutes. It applies only
before the first bookmark; changing it does not rewind an existing position.

Protect the configuration and queue with NTFS permissions, using the same user
that will run the collector:

```powershell
$collectorSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
New-Item -ItemType Directory -Force .local\collector | Out-Null
icacls .env.windows /inheritance:r /grant:r "*$($collectorSid):(F)"
icacls .local\collector /inheritance:r /grant:r "*$($collectorSid):(OI)(CI)F"
```

Check that each command succeeds. POSIX `chmod` does not implement Windows ACL
protection. The queue contains event details and is not separately encrypted.
The config reader accepts literal `KEY=VALUE` lines, not PowerShell expressions;
environment variables override the file.

## 3. Check and enable auditing in the lab

Windows only records events enabled by its audit policy. First record the current
policy so you can restore it:

```powershell
$auditBackup = Join-Path $PWD ("audit-policy-before-" + (Get-Date -Format yyyyMMdd-HHmmss) + ".csv")
auditpol /backup "/file:$auditBackup"
auditpol /get /category:*
```

For an English-language, standalone lab VM, enable the relevant subcategories:

```powershell
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable
auditpol /set /subcategory:"Special Logon" /success:enable
auditpol /set /subcategory:"Process Creation" /success:enable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable
auditpol /set /subcategory:"Security System Extension" /success:enable
```

On a localized installation, find the matching names or GUIDs with
`auditpol /list /subcategory:* /v`. Domain Group Policy can override local settings;
check the effective policy after applying changes. To restore this lab's saved
policy, use `auditpol /restore "/file:$auditBackup"` (or the saved file's full path).

Process event 4688 may have an empty command line. To include it, the optional
policy is **Computer Configuration → Administrative Templates → System → Audit
Process Creation → Include command line in process creation events**. Enable it
only if you want command arguments recorded in the Security log and SIEM; those
arguments can contain credentials. Record its original setting separately from
the auditpol backup and restore it separately when finished.

## 4. Collect, restart, and inspect

```powershell
.\.venv\Scripts\python.exe -m collectors.main --env-file .env.windows --once
.\.venv\Scripts\python.exe -m collectors.main --env-file .env.windows --status
.\.venv\Scripts\python.exe -m collectors.main --env-file .env.windows --duration 60
```

Or omit `--duration` to keep collecting until Ctrl-C. `--once` captures a fixed
latest record boundary and drains available queued work. Successful empty delivery
exits 0; remaining pending/rejected events or capture errors exit 2; configuration,
storage, or delivery blockers exit 1. A failed native query is a capture error,
not an empty successful read. Duration limits are checked between operations.

While collecting, run a harmless `whoami /user` in a second terminal after enabling
process creation auditing. Look for native event 4688 and its SIEM counterpart.
Verify through the Mac's API docs at `http://127.0.0.1:8000/docs` using the analyst
key: `GET /api/v1/events` with `os=windows` and this collector's `endpoint_id`.
Compare event codes, record IDs, hostname, times, and process IDs with Event Viewer.

Run `--once` again using the same state directory. Previously captured native
records must not create duplicate backend events. New activity on Windows can
legitimately increase counts. `--status` shows endpoint identity, queue counters,
bookmark presence, source errors, and explicit replay history without printing
event messages or keys. Stop the collector before using `--status` or `--drain`;
the state directory has an exclusive process lock on Windows as well as macOS.

To exercise buffering, close the SSH tunnel, collect briefly, and check that
`pending` increases. Reopen the tunnel and restart the collector; it should resume
delivery after its persisted retry delay and reduce `pending` to zero. `--drain`
only sends already queued records and respects the retry timer.

Local interactive logons frequently lack a source IP, so they are stored but do
not satisfy the two IP-based authentication detections. Do not create repeated
failed logons against a real account just to test alerts; the synthetic pipeline
test and Mac's `scripts/detection_demo.py` verify those rules without lockouts.

## 5. Handle expired bookmarks or cleared logs

Every native batch is limited to 100 events, 8 MiB rendered XML, and 256 KiB per
event. Each `EvtNext` wait is at most one second. The reader scans Security records
in native order and only queues the supported mappings below. Bookmark XML and a
fingerprint of the last native record are committed with the selected payloads in
one SQLite transaction. Full queues and malformed selected records retain the old
bookmark; initial read failures retain the original lookback start time.

On resume, strict seeking and fingerprint comparison detect a missing bookmarked
record or reuse of its record ID. This can happen after retention rollover or log
clearing. The collector records `source_error=SourceGap`, stops capture with exit
2, and retains its queue. **It does not silently skip to the end of the new log.**

Inspect the log and retention policy, then explicitly acknowledge a replay:

```powershell
.\.venv\Scripts\python.exe -m collectors.main --env-file .env.windows --reset-windows-bookmark
.\.venv\Scripts\python.exe -m collectors.main --env-file .env.windows --once
```

Recovery starts at the oldest **retained** Security record. It preserves endpoint
identity, queued data, and sent receipts; backend idempotency protects exact event
replays. Deleted records cannot be recovered. Each reset is recorded in local
status. Access-denied failures need permission repair, not a bookmark reset.

Event 1102 is normalized and detected once ingested, but a clearing operation that
invalidates the previous bookmark requires this explicit recovery before the new
1102 can be collected. Continuous automatic recovery and central collector-health
alerts are future work. Do not clear a real Security log for this test; use the
synthetic 1102 fixture. Replays older than the default 24-hour detection lateness
limit are stored but skipped by the detection worker.

## Event coverage and identity

| Native code | Normalized type | Account and other context |
| --- | --- | --- |
| 4624 / 4625 | `login_success` / `login_failure` | Target account, domain/SID, source IP, logon type in raw data |
| 4634 | `logout` | Target account |
| 4648 | `security_tool_event` | Explicit-credential attempt; subject and target, not proof of success |
| 4672 | `privilege_assigned` | Subject; assigned privilege list retained when present |
| 4688 | `process_created` | Subject, new process ID/path, parent ID/path, optional command line |
| 4697 | `service_installed` | Subject; service name/path retained in raw data |
| 4720 / 4726 | `account_created` / `account_deleted` | Subject actor and target account |
| 4728 / 4732 / 4756 | `group_membership_changed` | Actor, target group, and added member kept distinct; global/local/universal groups |
| 4740 | `security_tool_event` | Account lockout with actor and target |
| 1102 | `security_log_cleared` | Eventlog provider's `UserData/LogFileCleared` actor |

Mappings verify the channel and provider. Other event codes are skipped. A group
addition is not automatically labeled privilege escalation; the group determines
its meaning. Event data is parsed by named XML fields and is independent of the
localized rendered message. The parser rejects malformed, oversized, and
entity-defining XML. It preserves native timestamp precision in the raw data and
event identity, and emits a timezone-aware UTC timestamp. Native record ID, time,
computer, provider, code/version, and named data determine the endpoint-scoped UUID.
Record ID reuse after clearing therefore produces a different UUID.

The two authentication rules are now version 2: they correlate endpoint, OS,
source, username, domain, and IP, while retaining SID as evidence. Failed Windows
logons often use unknown SID `S-1-0-0` whereas success resolves a real SID. Including
SID in the group would prevent these from correlating. Text remains exact and
case-sensitive; missing domain versus present domain still differs. Account name
reuse within a detection window can combine distinct SIDs and requires analyst
review. Existing alerts and completed jobs are not rewritten by this change.

## Verification status

Local tests cover synthetic native XML, parser-to-backend schema compatibility,
native API behavior through fakes, atomic bookmark recovery, and XML → SQLite →
sender → FastAPI → real MongoDB → three alerts with duplicate replay. A Windows CI
job additionally runs collector tests with pywin32 installed and an actual
read-only Application-log API smoke test. Adding that job does not mean it has run.

**Live Security-log collection is deferred at the user's request because no Windows
VM is currently available. This does not block further project development.**
Passing portable tests is not evidence that auditing, Security log
permissions, VM networking, and installed pywin32 work in that VM. Complete steps
1–4 and record those results before claiming live Windows coverage.

## Primary references

- [Microsoft: bookmark creation and persistence](https://learn.microsoft.com/en-us/windows/win32/wes/bookmarking-events)
- [Microsoft: strict seeking and missing bookmarks](https://learn.microsoft.com/en-us/windows/win32/api/winevt/ne-winevt-evt_seek_flags)
- [pywin32: EvtSeek argument order](https://timgolden.me.uk/pywin32-docs/win32evtlog__EvtSeek_meth.html)
- [Microsoft: event 4625 and unknown target SID](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)
- [Microsoft: event 1102 XML](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102)
- [Microsoft: auditpol settings](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol-set)
- [Microsoft: command-line process auditing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing)
