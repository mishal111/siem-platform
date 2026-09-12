import pytest
from pymongo.errors import AutoReconnect

from app.repository import InvalidCursor


@pytest.mark.parametrize(
    "path",
    [
        "/alerts",
        "/alerts/0123456789abcdef01234567",
        "/alerts/0123456789abcdef01234567/events",
        "/detections/rules",
        "/detections/status",
    ],
)
def test_alerts_and_detection_metadata_require_analyst(client, collector_headers, path):
    assert client.get("/api/v1" + path).status_code == 401
    assert client.get("/api/v1" + path, headers=collector_headers).status_code == 401


@pytest.mark.parametrize(
    "query",
    [
        "limit=0",
        "limit=201",
        "severity=invalid",
        "status=invalid",
        "unexpected=value",
        "start_time=2026-09-11T00:00:00Z&end_time=2026-09-10T00:00:00Z",
    ],
)
def test_alert_filter_validation(client, analyst_headers, query):
    assert client.get("/api/v1/alerts?" + query, headers=analyst_headers).status_code == 422


def test_alert_not_found_and_bad_ids(client, repository, analyst_headers):
    repository.get_alert.return_value = None
    repository.alert_evidence.return_value = None
    for suffix in ("", "/events"):
        assert (
            client.get(
                "/api/v1/alerts/0123456789abcdef01234567" + suffix, headers=analyst_headers
            ).status_code
            == 404
        )
        assert client.get("/api/v1/alerts/bad" + suffix, headers=analyst_headers).status_code == 422


def test_alert_cursor_and_database_errors(client, repository, analyst_headers):
    repository.search_alerts.side_effect = InvalidCursor
    assert client.get("/api/v1/alerts?cursor=bad", headers=analyst_headers).status_code == 422
    repository.search_alerts.side_effect = AutoReconnect("sensitive-connection-details")
    response = client.get("/api/v1/alerts", headers=analyst_headers)
    assert response.status_code == 503 and "sensitive-connection-details" not in response.text


def test_six_rules_are_documented(client, analyst_headers):
    rules = client.get("/api/v1/detections/rules", headers=analyst_headers).json()
    assert {rule["rule_id"] for rule in rules} == {
        "AUTH-BRUTE-001",
        "AUTH-SUCCESS-001",
        "WIN-LOG-CLEAR-001",
        "WIN-ACCOUNT-001",
        "WIN-GROUP-001",
        "WIN-PS-001",
    }
