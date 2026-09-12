"""Exercise the running local API using keys from .env, without displaying secrets."""

import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
API = "http://127.0.0.1:8000/api/v1"


def request(method, path, key=None, payload=None):
    headers = {"Content-Type": "application/json"}
    if key:
        headers["X-API-Key"] = key
    body = json.dumps(payload).encode() if payload is not None else None
    req = Request(API + path, data=body, headers=headers, method=method)
    try:
        with urlopen(req, timeout=15) as response:
            return response.status, json.load(response)
    except HTTPError as exc:
        return exc.code, json.load(exc)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    env = {}
    for line in (ROOT / ".env").read_text().splitlines():
        if line and not line.startswith("#") and "=" in line:
            name, value = line.split("=", 1)
            env[name] = value.strip().strip("\"'")
    collector = env["COLLECTOR_API_KEY"]
    analyst = env["ANALYST_API_KEY"]
    status, _ = request("GET", "/health/ready")
    require(status == 200, "API database readiness failed")
    payload = {
        "event_uid": str(uuid4()),
        "endpoint_id": "synthetic-smoke-test",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "hostname": "DEMO-WINDOWS",
        "os": "windows",
        "source": "synthetic",
        "event_type": "login_failure",
        "event_code": 4625,
        "username": "demo-user",
        "source_ip": "192.0.2.20",
        "severity": "medium",
        "message": "Synthetic failed login for backend smoke testing",
    }
    status, first = request("POST", "/events", collector, payload)
    require(status == 201, "Event ingestion failed (HTTP {})".format(status))
    status, repeated = request("POST", "/events", collector, payload)
    require(status == 200 and repeated["duplicate"], "Duplicate detection failed")
    require(first["event"] == repeated["event"], "Duplicate response changed the stored event")
    record_id = first["event"]["id"]
    status, event = request("GET", "/events/" + record_id, analyst)
    require(status == 200 and event == first["event"], "Stored event retrieval failed")
    status, page = request("GET", "/events?endpoint_id=synthetic-smoke-test&limit=5", analyst)
    require(status == 200 and page["items"], "Event search failed")
    status, _ = request("GET", "/events", collector)
    require(status == 401, "Collector key unexpectedly permitted analyst access")
    print(
        "PASS: readiness, ingestion, duplicate protection, retrieval, search, and role separation."
    )
    print("Stored one synthetic demonstration event: " + record_id)


if __name__ == "__main__":
    try:
        main()
    except (OSError, URLError, KeyError, RuntimeError, ValueError) as exc:
        # Avoid displaying raw network exceptions or request headers.
        raise SystemExit(
            "Smoke test failed ({}). Check .env and docker compose ps/logs.".format(
                type(exc).__name__
            )
        ) from None
