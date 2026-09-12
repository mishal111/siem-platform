from datetime import UTC, datetime, timedelta

import pytest
from collectors.common.config import Config
from collectors.common.sender import Sender
from collectors.common.spool import Spool
from collectors.tests.windows_fixtures import windows_xml
from collectors.windows.parser import normalize
from fastapi.testclient import TestClient

from app.detections.worker import DetectionWorker
from app.main import create_app


@pytest.mark.integration
def test_windows_xml_queue_api_detection_and_duplicate_replay(
    mongo_repository, collector_headers, analyst_headers, tmp_path
):
    settings, repository = mongo_repository
    now = datetime.now(UTC)
    base = datetime.fromtimestamp(int(now.timestamp()) // 300 * 300, UTC) - timedelta(minutes=10)
    xml_rows = [
        windows_xml(
            code, record=100 + index, stamp=(base + timedelta(seconds=index * 10)).isoformat()
        )
        for index, code in enumerate([4625] * 5 + [4624, 1102])
    ]
    with Spool(tmp_path) as spool, TestClient(create_app(settings)) as client:
        events = [normalize(xml, spool.endpoint_id) for xml in xml_rows]
        assert events[0]["user_sid"] is None
        assert events[5]["user_sid"] is not None
        spool.enqueue_batch(events, {"windows_position": "synthetic-checkpoint"})

        # Exercise the real sender and its receipt validation against the real API.
        class APITransport:
            def post(self, event):
                response = client.post("/api/v1/events", json=event, headers=collector_headers)
                return response.status_code, response.content, response.headers

        sender = Sender(Config(api_key="a" * 64), spool, transport=APITransport())
        while sender.drain():
            pass
        assert spool.status()["pending"] == spool.status()["rejected"] == 0
        assert spool.status()["delivered_total"] == 7
        worker = DetectionWorker(repository, settings)
        for _ in range(20):
            if not worker.process_one():
                break
        page = client.get("/api/v1/alerts", headers=analyst_headers).json()
        assert {alert["rule_id"] for alert in page["items"]} == {
            "AUTH-BRUTE-001",
            "AUTH-SUCCESS-001",
            "WIN-LOG-CLEAR-001",
        }
        assert len(page["items"]) == 3
        for alert in page["items"]:
            assert alert["rule_version"] == (1 if alert["rule_id"] == "WIN-LOG-CLEAR-001" else 2)
            evidence = client.get(
                f"/api/v1/alerts/{alert['id']}/events", headers=analyst_headers
            ).json()
            assert len(evidence["items"]) == alert["event_count"]
            assert evidence["missing_event_ids"] == []
        for event in events:
            response = client.post("/api/v1/events", json=event, headers=collector_headers)
            assert response.status_code == 200
            assert response.json()["duplicate"]
        assert not worker.process_one()
        assert repository.collection.count_documents({}) == 7
        assert repository.alerts.collection.count_documents({}) == 3
