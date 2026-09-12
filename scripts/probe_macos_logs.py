"""Read a narrow recent log window and report field availability, never message contents."""

import collections
import json
import subprocess

PREDICATE = (
    '(process == "sshd" OR process == "sshd-session" OR process == "sudo" OR '
    'process == "loginwindow" OR process == "authd" OR process == "securityd" OR '
    'process == "syspolicyd" OR process == "XProtectService" OR process == "XProtectRemediator")'
)


def main():
    result = subprocess.run(
        [
            "/usr/bin/log",
            "show",
            "--last",
            "5m",
            "--style",
            "ndjson",
            "--info",
            "--no-pager",
            "--predicate",
            PREDICATE,
        ],
        capture_output=True,
        timeout=30,
    )
    if result.returncode:
        print(json.dumps({"status": "log_access_failed", "returncode": result.returncode}))
        raise SystemExit(1)
    rows = []
    invalid = 0
    for line in result.stdout.splitlines():
        try:
            item = json.loads(line)
            if isinstance(item, dict):
                rows.append(item)
        except (ValueError, UnicodeError):
            invalid += 1
    counts = collections.Counter()
    for row in rows:
        counts[str(row.get("processImagePath", "unknown")).rsplit("/", 1)[-1]] += 1
    print(
        json.dumps(
            {
                "status": "ok",
                "records": len(rows),
                "non_json_lines": invalid,
                "process_counts": dict(counts),
                "available_fields": sorted({key for row in rows for key in row}),
                "records_with_private_markers": sum(
                    "<private>" in str(row.get("eventMessage", "")) for row in rows
                ),
                "timestamp_examples": [row.get("timestamp") for row in rows[:2]],
                "has_mach_timestamp": sum("machTimestamp" in row for row in rows),
                "has_boot_uuid": sum("bootUUID" in row for row in rows),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
