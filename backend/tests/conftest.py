import os
from datetime import UTC, datetime
from unittest.mock import create_autospec
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.identity import UserCreate, hash_password, token_hash
from app.main import create_app
from app.models import EventInput, EventPage, EventRecord
from app.repository import EventRepository

COLLECTOR_KEY = "test-collector-" + "c" * 32
ANALYST_KEY = "test-analyst-" + "a" * 32
USER_PASSWORD = "synthetic-test-password-42"


@pytest.fixture(scope="session")
def fixture_password_hash():
    return hash_password(USER_PASSWORD)


@pytest.fixture
def managed(mongo_repository, fixture_password_hash):
    from datetime import timedelta
    from unittest.mock import patch

    settings, repository = mongo_repository
    identities = {}
    for role in ("admin", "analyst", "viewer"):
        with patch("app.identity.hash_password", return_value=fixture_password_hash):
            user = repository.identity.create_user(
                UserCreate(username="test-" + role, role=role, password=USER_PASSWORD),
                "test-fixture",
            )
        token = "test-session-" + uuid4().hex
        repository.identity.sessions.insert_one(
            {
                "_id": token_hash(token),
                "user_id": user.id,
                "auth_version": 0,
                "expires_at": datetime.now(UTC) + timedelta(hours=1),
            }
        )
        identities[role] = (user, {"Authorization": "Bearer " + token})
    # The app owns its connection; the fixture keeps a separate connection for teardown.
    with TestClient(create_app(settings)) as client:
        yield settings, repository, client, identities


@pytest.fixture
def settings():
    return Settings(
        _env_file=None,
        collector_api_key=COLLECTOR_KEY,
        analyst_api_key=ANALYST_KEY,
        max_request_bytes=4096,
    )


@pytest.fixture
def collector_headers():
    return {"X-API-Key": COLLECTOR_KEY}


@pytest.fixture
def analyst_headers():
    return {"X-API-Key": ANALYST_KEY}


@pytest.fixture
def payload():
    return {
        "event_uid": str(uuid4()),
        "endpoint_id": "windows-lab-01",
        "timestamp": "2026-09-10T12:30:00.123456+05:30",
        "hostname": "WIN11-LAB",
        "os": "windows",
        "source": "Security",
        "event_type": "login_failure",
        "event_code": 4625,
        "username": "administrator",
        "source_ip": "192.168.1.20",
        "severity": "medium",
        "message": "An account failed to log on",
        "raw_event": {"TargetUserName": "administrator"},
    }


@pytest.fixture
def record(payload):
    return EventRecord(
        **EventInput.model_validate(payload).model_dump(),
        id="0123456789abcdef01234567",
        received_at=datetime.now(UTC),
    )


@pytest.fixture
def repository(record):
    store = create_autospec(EventRepository, instance=True)
    store.insert.return_value = (record, False)
    store.get.return_value = record
    store.search.return_value = EventPage(items=[record], next_cursor=None)
    return store


@pytest.fixture
def client(settings, repository):
    with TestClient(create_app(settings, repository)) as client:
        yield client


@pytest.fixture
def mongo_repository():
    uri = os.environ.get("TEST_MONGO_URI")
    if not uri:
        pytest.skip("Set TEST_MONGO_URI to run real MongoDB integration tests")
    database = "siem_test_" + uuid4().hex
    settings = Settings(
        _env_file=None,
        mongo_uri=uri,
        mongo_db=database,
        collector_api_key=COLLECTOR_KEY,
        analyst_api_key=ANALYST_KEY,
    )
    repository = EventRepository(settings)
    repository.initialize()
    try:
        yield settings, repository
    finally:
        # Only this fixture's uniquely named database is removed.
        repository.client.drop_database(database)
        repository.close()
