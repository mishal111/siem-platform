import hashlib
import ipaddress
import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from uuid import UUID, uuid5

from collectors import VERSION
from collectors.common.errors import ParseError

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
AUDIT_PROVIDER = "Microsoft-Windows-Security-Auditing"
EVENTLOG_PROVIDER = "Microsoft-Windows-Eventlog"
MAX_XML_BYTES = 256 * 1024
EVENT_TYPES = {
    4624: "login_success",
    4625: "login_failure",
    4634: "logout",
    4648: "security_tool_event",  # Explicit credentials attempted, not a confirmed login.
    4672: "privilege_assigned",
    4688: "process_created",
    4697: "service_installed",
    4720: "account_created",
    4726: "account_deleted",
    4728: "group_membership_changed",
    4732: "group_membership_changed",
    4756: "group_membership_changed",
    4740: "security_tool_event",
    1102: "security_log_cleared",
}


def parse_xml(xml):
    if not isinstance(xml, str) or len(xml.encode("utf-8")) > MAX_XML_BYTES:
        raise ParseError("Invalid or oversized Windows event XML")
    if re.search(r"<!\s*(?:DOCTYPE|ENTITY)", xml, re.I):
        raise ParseError("XML declarations defining entities are not supported")
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as exc:
        raise ParseError("Malformed Windows event XML") from exc
    if root.tag != NS + "Event":
        raise ParseError("Expected a Windows Event element")
    return root


def record_id(xml):
    try:
        return int(parse_xml(xml).findtext(NS + "System/" + NS + "EventRecordID"))
    except (TypeError, ValueError) as exc:
        raise ParseError("Missing Windows event record ID") from exc


def fingerprint(xml):
    return hashlib.sha256(xml.encode("utf-8")).hexdigest()


def optional(value):
    return None if value in (None, "", "-", "S-1-0-0") else value


def number(value):
    value = optional(value)
    if value is None:
        return None
    result = int(value, 16 if value.lower().startswith("0x") else 10)
    if not 0 <= result < 2**63:
        raise ValueError("Number outside supported range")
    return result


def normalize(xml, endpoint_id):
    root = parse_xml(xml)
    try:
        system = root.find(NS + "System")
        code = int(system.findtext(NS + "EventID"))
        channel = system.findtext(NS + "Channel")
        if channel != "Security" or code not in EVENT_TYPES:
            return None
        provider = system.find(NS + "Provider").attrib.get("Name")
        expected = EVENTLOG_PROVIDER if code == 1102 else AUDIT_PROVIDER
        if provider != expected:
            return None
        native_time = system.find(NS + "TimeCreated").attrib["SystemTime"]
        stamp = re.fullmatch(
            r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,7}))?(Z|[+-]\d{2}:\d{2})",
            native_time,
        )
        if stamp is None:
            raise ValueError("Invalid Windows timestamp")
        # Windows uses 100 ns precision; Python 3.9 only accepts 3 or 6 fractional digits.
        # Preserve the original seven digits in the raw event and deterministic identity.
        fraction = (stamp[2] or "0")[:6].ljust(6, "0")
        timestamp = datetime.fromisoformat(
            stamp[1] + "." + fraction + stamp[3].replace("Z", "+00:00")
        )
        if timestamp.utcoffset() is None:
            raise ValueError("Timestamp requires a timezone")
        hostname = system.findtext(NS + "Computer")
        native_id = str(record_id(xml))
        data = {}
        if code == 1102:
            # 1102 uses UserData/LogFileCleared in a separate namespace, not EventData.
            user_data = root.find(NS + "UserData")
            nodes = [] if user_data is None else user_data.iter()
            pairs = [(node.tag.rsplit("}", 1)[-1], node.text) for node in nodes if len(node) == 0]
        else:
            pairs = [
                (node.get("Name"), node.text)
                for node in root.findall(NS + "EventData/" + NS + "Data")
            ]
        for key, value in pairs:
            if not key or key in data or len(key) > 255:
                raise ValueError("Missing or duplicate data name")
            data[key] = value or ""
        if len(data) > 128:
            raise ValueError("Too many event fields")
        prefix = "Target" if code in (4624, 4625, 4634) else "Subject"
        fields = {
            "username": optional(data.get(prefix + "UserName")),
            "user_domain": optional(data.get(prefix + "DomainName")),
            "user_sid": optional(data.get(prefix + "UserSid")),
        }
        if code in (4648, 4720, 4726, 4740):
            fields.update(
                target_username=optional(data.get("TargetUserName")),
                target_user_sid=optional(data.get("TargetSid")),
            )
        if code in (4728, 4732, 4756):
            fields.update(
                group_name=optional(data.get("TargetUserName")),
                group_sid=optional(data.get("TargetSid")),
                target_username=optional(data.get("MemberName")),
                target_user_sid=optional(data.get("MemberSid")),
            )
        if code in (4624, 4625, 4648):
            try:
                address = ipaddress.ip_address(data.get("IpAddress", ""))
                fields["source_ip"] = str(getattr(address, "ipv4_mapped", None) or address)
            except ValueError:
                fields["source_ip"] = None
            fields.update(
                process_name=optional(data.get("ProcessName")),
                process_id=number(data.get("ProcessId")),
            )
        if code == 4688:
            fields.update(
                process_name=optional(data.get("NewProcessName")),
                process_id=number(data.get("NewProcessId")),
                parent_process_name=optional(data.get("ParentProcessName")),
                parent_process_id=number(data.get("ProcessId")),
                command_line=optional(data.get("CommandLine")),
            )
        limits = {"process_name": 4096, "parent_process_name": 4096, "command_line": 32768}
        for key, value in {"hostname": hostname, **fields}.items():
            if isinstance(value, str) and not 1 <= len(value) <= limits.get(key, 255):
                raise ValueError("Field outside contract bounds")
        if not hostname or int(native_id) < 0:
            raise ValueError("Missing native identity")
        # Use native precision and named fields so replay is stable, including after ID reuse.
        raw = {
            "system": {
                "computer": hostname,
                "provider": provider,
                "channel": channel,
                "record_id": native_id,
                "event_id": code,
                "system_time": native_time,
                "version": system.findtext(NS + "Version"),
            },
            "data": data,
        }
        digest = hashlib.sha256(json.dumps(raw, sort_keys=True).encode()).hexdigest()
        return {
            "schema_version": 1,
            "event_uid": str(uuid5(UUID(endpoint_id), digest)),
            "endpoint_id": endpoint_id,
            "timestamp": timestamp.astimezone(timezone.utc).isoformat(),
            "hostname": hostname,
            "os": "windows",
            "source": channel,
            "source_record_id": native_id,
            "provider": provider,
            "collector_version": VERSION,
            "event_type": EVENT_TYPES[code],
            "event_code": code,
            "severity": "critical" if code == 1102 else "medium" if code == 4625 else "info",
            "message": "Windows Security event {}: {}".format(code, EVENT_TYPES[code]),
            "raw_event": raw,
            **fields,
        }
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError) as exc:
        raise ParseError("Invalid Windows event identity or fields") from exc
