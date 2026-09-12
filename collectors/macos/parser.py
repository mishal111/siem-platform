import hashlib
import ipaddress
import json
import re
from datetime import datetime, timezone
from pathlib import PurePosixPath
from uuid import UUID, uuid5

from collectors import VERSION
from collectors.common.errors import ParseError

SSH_AUTH = re.compile(
    r"^(?P<result>Failed|Accepted) (?:password|publickey|keyboard-interactive(?:/pam)?) "
    r"for (?P<invalid>invalid user )?(?P<user>\S+) from (?P<ip>\S+) port \d+(?:\s|$)"
)
SUDO_COMMAND = re.compile(
    r"^\s*(?P<user>[^\s:;]+)\s*:\s*TTY=[^;]*;\s*PWD=[^;]*;\s*"
    r"USER=(?P<target>[^;\s]+)\s*;\s*COMMAND=(?P<command>.+)$"
)
SUDO_FAILURE = re.compile(
    r"^\s*(?P<user>[^\s:;]+)\s*:\s*(?:\d+ incorrect password attempts?|"
    r"authentication failure|a password is required)(?:\s|;|$)",
    re.IGNORECASE,
)
SECURITY_DENIAL = re.compile(
    r"\b(?:malware|assessment denied|execution denied|quarantined)\b", re.I
)
RAW_FIELDS = (
    "bootUUID",
    "machTimestamp",
    "threadID",
    "traceID",
    "activityIdentifier",
    "subsystem",
    "category",
    "messageType",
    "processImageUUID",
    "senderImageUUID",
    "senderProgramCounter",
)


def known_user(value):
    return None if value in ("<private>", "(null)", "unknown") else value


def normalize(row, endpoint_id, hostname):
    if not isinstance(row, dict):
        raise ParseError("Expected a JSON log record")
    if "finished" in row and "eventMessage" not in row:
        return None  # `log show --style ndjson` ends with a summary object.
    process = PurePosixPath(str(row.get("processImagePath", ""))).name
    if process not in (
        "authd",
        "sshd",
        "sshd-session",
        "sudo",
        "syspolicyd",
        "XProtectService",
        "XProtectRemediator",
    ):
        return None
    message = row.get("eventMessage")
    if not isinstance(message, str):
        raise ParseError("Selected process record has no text message")
    fields = {"event_type": "security_tool_event", "severity": "info"}
    if process in ("sshd", "sshd-session"):
        match = SSH_AUTH.match(message)
        if not match:
            return None
        fields.update(
            event_type="login_success" if match["result"] == "Accepted" else "login_failure",
            username=known_user(match["user"]),
        )
        try:
            fields["source_ip"] = str(ipaddress.ip_address(match["ip"]))
        except ValueError:
            fields["source_ip"] = None
    elif process == "sudo":
        command = SUDO_COMMAND.match(message)
        failure = SUDO_FAILURE.match(message)
        if command:
            fields.update(
                event_type="sudo_execution",
                username=known_user(command["user"]),
                target_username=known_user(command["target"]),
                command_line=command["command"],
            )
        elif failure:
            fields.update(event_type="login_failure", username=known_user(failure["user"]))
        else:
            return None
    elif process != "authd" and not SECURITY_DENIAL.search(message):
        return None
    # Authorization daemon diagnostics are context, not proof of a user login or an attack.
    try:
        # Python 3.9 requires a colon in offsets; macOS emits +0530 / +0000.
        stamp = str(row["timestamp"]).replace("Z", "+00:00")
        stamp = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", stamp)
        timestamp = datetime.fromisoformat(stamp)
        if timestamp.utcoffset() is None:
            raise ValueError
        timestamp = timestamp.astimezone(timezone.utc).isoformat()
        process_id = row.get("processID")
        if process_id is not None and (
            not isinstance(process_id, int) or not 0 <= process_id < 2**63
        ):
            raise ValueError
        if len(message) > 32768:
            raise ValueError
        # Stable native identity supports overlapping reads and process restarts.
        identity = {key: row.get(key) for key in RAW_FIELDS}
        identity.update(
            timestamp=timestamp, process=process, process_id=process_id, message=message
        )
        digest = hashlib.sha256(
            json.dumps(identity, sort_keys=True, allow_nan=False).encode()
        ).hexdigest()
        uid = str(uuid5(UUID(endpoint_id), digest))
        raw = {}
        for key in RAW_FIELDS:
            value = row.get(key)
            if isinstance(value, (str, int, bool)):
                raw[key] = (
                    str(value)
                    if isinstance(value, int) and not -(2**63) <= value < 2**63
                    else value
                )
        return {
            "schema_version": 1,
            "event_uid": uid,
            "endpoint_id": endpoint_id,
            "timestamp": timestamp,
            "hostname": hostname,
            "os": "macos",
            "source": "macos.unified_log",
            "source_record_id": digest,
            "provider": process,
            "collector_version": VERSION,
            "process_name": process,
            "process_id": process_id,
            "message": message,
            "raw_event": raw,
            **fields,
        }
    except (KeyError, ValueError, TypeError, OverflowError) as exc:
        raise ParseError("Invalid timestamp, identity, or fields in selected log record") from exc
