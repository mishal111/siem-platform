"""Synthetic XML with the native event schemas; no real accounts or log data."""

import xml.etree.ElementTree as ET

from collectors.windows.parser import AUDIT_PROVIDER, EVENTLOG_PROVIDER, NS

ENDPOINT = "19f57503-dae2-47fa-8871-6939211fa97e"
SUBJECT = {
    "SubjectUserName": "operator",
    "SubjectDomainName": "LAB",
    "SubjectUserSid": "S-1-5-21-100-200-300-1001",
}
TARGET = {
    "TargetUserName": "alice",
    "TargetDomainName": "LAB",
    "TargetUserSid": "S-1-5-21-100-200-300-1002",
}


def windows_xml(
    code=4625,
    record=100,
    stamp="2026-09-10T12:00:00.1234567Z",
    data=None,
    provider=None,
    channel="Security",
):
    root = ET.Element(NS + "Event")
    system = ET.SubElement(root, NS + "System")
    ET.SubElement(
        system,
        NS + "Provider",
        Name=provider or (EVENTLOG_PROVIDER if code == 1102 else AUDIT_PROVIDER),
    )
    for name, value in {
        "EventID": code,
        "Version": 0,
        "EventRecordID": record,
        "Channel": channel,
        "Computer": "WIN-LAB",
    }.items():
        ET.SubElement(system, NS + name).text = str(value)
    ET.SubElement(system, NS + "TimeCreated", SystemTime=stamp)
    ET.SubElement(system, NS + "Execution", ProcessID="999", ThreadID="12")
    fields = dict(SUBJECT)
    if code in (4624, 4625, 4634, 4648):
        fields.update(
            TARGET,
            IpAddress="::ffff:192.0.2.20",
            ProcessId="0x250",
            ProcessName="C:\\Windows\\System32\\lsass.exe",
            LogonType="3",
        )
        if code == 4625:
            fields.update(TargetUserSid="S-1-0-0", Status="0xc000006d", SubStatus="0xc000006a")
    elif code == 4688:
        fields.update(
            NewProcessName="C:\\Windows\\System32\\whoami.exe",
            NewProcessId="0x1234",
            ProcessId="0x456",
            ParentProcessName="C:\\Windows\\System32\\cmd.exe",
            CommandLine="whoami /user",
        )
    elif code in (4720, 4726, 4740):
        fields.update(TargetUserName="new-user", TargetSid="S-1-5-21-100-200-300-1010")
    elif code in (4728, 4732, 4756):
        fields.update(
            TargetUserName="Administrators",
            TargetSid="S-1-5-32-544",
            MemberName="-",
            MemberSid="S-1-5-21-100-200-300-1010",
        )
    elif code == 4697:
        fields.update(ServiceName="LabService", ServiceFileName="C:\\Lab\\service.exe")
    if data:
        fields.update(data)
    if code == 1102:
        node = ET.SubElement(root, NS + "UserData")
        user_ns = "{http://manifests.microsoft.com/win/2004/08/windows/eventlog}"
        node = ET.SubElement(node, user_ns + "LogFileCleared")
        for name, value in fields.items():
            ET.SubElement(node, user_ns + name).text = value
    else:
        node = ET.SubElement(root, NS + "EventData")
        for name, value in fields.items():
            ET.SubElement(node, NS + "Data", Name=name).text = value
    return ET.tostring(root, encoding="unicode")
