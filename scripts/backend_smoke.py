"""Exercise backend login, enrollment, six detections, investigation, replay and revocation."""

import argparse
import base64
import json
import secrets
import ssl
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from collectors.tests.windows_fixtures import windows_xml  # noqa: E402
from collectors.windows.parser import normalize  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deployment", action="store_true")
    args = parser.parse_args()
    credentials = json.loads(
        (
            ROOT
            / ".local"
            / ("deployment-admin-credentials.json" if args.deployment else "admin-credentials.json")
        ).read_text()
    )
    base = "https://localhost:8443" if args.deployment else "http://127.0.0.1:8000"
    context = (
        ssl.create_default_context(cafile=str(ROOT / ".local/deployment-ca.crt"))
        if args.deployment
        else ssl.create_default_context()
    )
    opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context))

    def call(method, path, headers=None, body=None, expected=200):
        request = Request(
            base + "/api/v1" + path,
            method=method,
            headers={"Content-Type": "application/json", **(headers or {})},
            data=json.dumps(body).encode() if body is not None else None,
        )
        try:
            with opener.open(request, timeout=15) as response:
                status, content = response.status, response.read()
        except HTTPError as error:
            status, content = error.code, error.read()
        if status != expected:
            raise RuntimeError(
                "Unexpected HTTP {} during {} {}".format(status, method, path.split("?")[0])
            )
        return json.loads(content) if content else None

    def login(username, password):
        session = call("POST", "/auth/login", body={"username": username, "password": password})
        return {"Authorization": "Bearer " + session["access_token"]}

    admin = login(credentials["username"], credentials["password"])
    run_id = str(uuid4())
    synthetic_users = []
    try:
        assert call("GET", "/auth/me", admin)["role"] == "admin"
        for role in ("viewer", "analyst"):
            password = secrets.token_urlsafe(24)
            user = call(
                "POST",
                "/users",
                admin,
                {
                    "username": "check-" + role + "-" + run_id[:8],
                    "role": role,
                    "password": password,
                },
                201,
            )
            synthetic_users.append(user)
            user["headers"] = login(user["username"], password)
        viewer, analyst = synthetic_users
        call("GET", "/users", viewer["headers"], expected=403)
        enrollment = call(
            "POST",
            "/endpoints",
            admin,
            {"endpoint_id": run_id, "hostname": "SYNTHETIC-BACKEND-CHECK", "os": "windows"},
            201,
        )
        collector = {"X-API-Key": enrollment["api_key"]}
        call("GET", "/events", collector, expected=401)
        current = datetime.now(timezone.utc)
        origin = datetime.fromtimestamp(int(current.timestamp()) // 300 * 300 - 300, timezone.utc)
        encoded = base64.b64encode("Write-Output 'synthetic test'".encode("utf-16-le")).decode()
        events = []
        for index, code in enumerate([4625] * 5 + [4624, 1102, 4720, 4732, 4688]):
            fields = (
                {
                    "NewProcessName": "powershell.exe",
                    "CommandLine": "powershell.exe -EncodedCommand " + encoded,
                }
                if code == 4688
                else None
            )
            xml = windows_xml(
                code,
                record=100 + index,
                stamp=(origin + timedelta(seconds=index * 10)).isoformat(),
                data=fields,
            ).replace("WIN-LAB", "SYNTHETIC-BACKEND-CHECK")
            event = normalize(xml, run_id)
            event["message"] = "Synthetic backend acceptance test: " + event["event_type"]
            event["raw_event"]["synthetic"] = True
            events.append(event)
            call("POST", "/events", collector, event, 201)
        for event in events:
            assert call("POST", "/events", collector, event)["duplicate"]
        expected_rules = {
            "AUTH-BRUTE-001",
            "AUTH-SUCCESS-001",
            "WIN-LOG-CLEAR-001",
            "WIN-ACCOUNT-001",
            "WIN-GROUP-001",
            "WIN-PS-001",
        }
        deadline = time.monotonic() + 30
        while True:
            alerts = call("GET", "/alerts?" + urlencode({"endpoint_id": run_id}), admin)["items"]
            if {row["rule_id"] for row in alerts} == expected_rules:
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("Six expected alerts did not arrive")
            time.sleep(0.5)
        assert len(alerts) == 6
        for alert in alerts:
            evidence = call("GET", "/alerts/" + alert["id"] + "/events", viewer["headers"])
            assert (
                not evidence["missing_event_ids"] and len(evidence["items"]) == alert["event_count"]
            )
        path = "/alerts/" + alerts[0]["id"]
        call(
            "PATCH",
            path,
            analyst["headers"],
            {"expected_revision": 0, "status": "investigating", "assigned_to": analyst["id"]},
        )
        note = {
            "note_id": str(uuid4()),
            "expected_revision": 1,
            "text": "Synthetic validation: evidence reviewed.",
        }
        call("POST", path + "/notes", analyst["headers"], note, 201)
        call("POST", path + "/notes", analyst["headers"], note, 201)
        call("PATCH", path, analyst["headers"], {"expected_revision": 2, "status": "resolved"})
        call("PATCH", path, analyst["headers"], {"expected_revision": 2, "status": "open"}, 409)
        assert len(call("GET", path + "/history", admin)["items"]) == 3
        assert len(call("GET", path + "/notes", admin)) == 1
        assert call("GET", "/hosts/" + run_id, admin)["event_count"] == 10
        assert call("GET", "/dashboard/summary", viewer["headers"])["event_count"] >= 10
        for event in events:
            call("POST", "/events", collector, event)
        replay = call("GET", "/alerts?" + urlencode({"endpoint_id": run_id}), admin)["items"]
        assert {row["id"] for row in replay} == {row["id"] for row in alerts}
        rotated = call(
            "POST", "/endpoints/" + run_id + "/rotate-key", admin, {"expected_revision": 0}
        )
        call("POST", "/events", collector, events[0], 401)
        new_key = {"X-API-Key": rotated["api_key"]}
        call("POST", "/events", new_key, events[0])
        call("PATCH", "/endpoints/" + run_id, admin, {"expected_revision": 1, "active": False})
        call("POST", "/events", new_key, events[0], 401)
        report = {
            "status": "passed",
            "deployment": "hardened_https" if args.deployment else "development",
            "synthetic_endpoint": run_id,
            "events": 10,
            "alerts": 6,
            "duplicate_replay": "passed",
            "roles_sessions": "passed",
            "workflow_audit": "passed",
            "key_rotation_revocation": "passed",
            "tls_certificate_verified": args.deployment,
        }
        (
            ROOT
            / ".local"
            / ("hardened-smoke-result.json" if args.deployment else "backend-smoke-result.json")
        ).write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    finally:
        for user in synthetic_users:
            call("PATCH", "/users/" + user["id"], admin, {"expected_revision": 0, "active": False})
        call("POST", "/auth/logout", admin, expected=204)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, AssertionError, RuntimeError) as error:
        raise SystemExit(
            str(error)
            if isinstance(error, RuntimeError)
            else "Backend smoke test failed; inspect local setup and test stage."
        ) from None
