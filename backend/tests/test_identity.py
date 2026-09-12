from datetime import UTC, datetime, timedelta

import pytest

from app.identity import token_hash
from tests.conftest import USER_PASSWORD

pytestmark = pytest.mark.integration


def test_login_me_logout_and_stored_token_hash(managed):
    _, repo, client, users = managed
    response = client.post(
        "/api/v1/auth/login", json={"username": "TEST-ADMIN", "password": USER_PASSWORD}
    )
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["user"]["role"] == "admin"
    assert response.headers["cache-control"] == "no-store"
    token = result["access_token"]
    stored = repo.identity.sessions.find_one({"_id": token_hash(token)})
    assert stored and token not in str(stored)
    headers = {"Authorization": "Bearer " + token}
    assert client.get("/api/v1/auth/me", headers=headers).json()["id"] == users["admin"][0].id
    assert client.post("/api/v1/auth/logout", headers=headers).status_code == 204
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 401


def test_wrong_unknown_and_disabled_accounts_return_same_error(managed):
    _, repo, client, users = managed
    wrong = client.post(
        "/api/v1/auth/login",
        json={"username": "test-admin", "password": "wrong-password-long-enough"},
    )
    unknown = client.post(
        "/api/v1/auth/login", json={"username": "missing-user", "password": USER_PASSWORD}
    )
    repo.identity.users.update_one({"_id": users["viewer"][0].id}, {"$set": {"active": False}})
    inactive = client.post(
        "/api/v1/auth/login", json={"username": "test-viewer", "password": USER_PASSWORD}
    )
    assert wrong.status_code == unknown.status_code == inactive.status_code == 401
    assert wrong.json() == unknown.json() == inactive.json()


def test_expiry_checked_without_waiting_for_mongo_ttl(managed):
    _, repo, client, users = managed
    user, headers = users["analyst"]
    repo.identity.sessions.update_many(
        {"user_id": user.id}, {"$set": {"expires_at": datetime.now(UTC) - timedelta(seconds=1)}}
    )
    assert client.get("/api/v1/events", headers=headers).status_code == 401


def test_only_admin_can_create_users_and_secrets_never_return(managed):
    _, repo, client, users = managed
    data = {"username": "new-analyst", "role": "analyst", "password": USER_PASSWORD}
    for role in ("analyst", "viewer"):
        assert client.post("/api/v1/users", headers=users[role][1], json=data).status_code == 403
    response = client.post("/api/v1/users", headers=users["admin"][1], json=data)
    assert response.status_code == 201
    row = repo.identity.users.find_one({"username": data["username"]})
    assert row["password_hash"]["algorithm"] == "scrypt-131072-8-1"
    assert USER_PASSWORD not in str(row)
    assert "password" not in response.text and "history" not in response.text
    listing = client.get("/api/v1/users", headers=users["admin"][1]).text
    assert row["password_hash"]["digest"] not in listing
    assert client.post("/api/v1/users", headers=users["admin"][1], json=data).status_code == 409


def test_user_update_revokes_sessions_and_rejects_stale_revision(managed):
    _, _, client, users = managed
    user, headers = users["analyst"]
    path = f"/api/v1/users/{user.id}"
    response = client.patch(
        path, headers=users["admin"][1], json={"expected_revision": 0, "role": "viewer"}
    )
    assert response.status_code == 200
    assert client.get("/api/v1/events", headers=headers).status_code == 401
    assert (
        client.patch(
            path, headers=users["admin"][1], json={"expected_revision": 0, "active": False}
        ).status_code
        == 409
    )
    audit = client.get(path + "/history", headers=users["admin"][1]).json()["items"]
    assert audit[-1]["actor_id"] == users["admin"][0].id
    assert audit[-1]["changes"] == {"role": "viewer"}


def test_admin_cannot_be_demoted_through_api(managed):
    _, _, client, users = managed
    user, headers = users["admin"]
    for patch in ({"active": False}, {"role": "viewer"}):
        assert (
            client.patch(
                f"/api/v1/users/{user.id}", headers=headers, json={"expected_revision": 0, **patch}
            ).status_code
            == 409
        )


def test_password_change_requires_current_password_and_revokes_old_sessions(managed):
    _, _, client, users = managed
    _, headers = users["viewer"]
    new_password = "different-test-password-43"
    assert (
        client.post(
            "/api/v1/auth/password",
            headers=headers,
            json={"current_password": "incorrect-password-44", "new_password": new_password},
        ).status_code
        == 401
    )
    assert (
        client.post(
            "/api/v1/auth/password",
            headers=headers,
            json={"current_password": USER_PASSWORD, "new_password": new_password},
        ).status_code
        == 200
    )
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 401
    assert (
        client.post(
            "/api/v1/auth/login", json={"username": "test-viewer", "password": USER_PASSWORD}
        ).status_code
        == 401
    )
    assert (
        client.post(
            "/api/v1/auth/login", json={"username": "test-viewer", "password": new_password}
        ).status_code
        == 200
    )


def test_durable_login_throttling_precedes_password_work(managed):
    from unittest.mock import patch

    _, repo, client, _ = managed
    repo.identity.settings.login_user_attempts = 1
    data = {"username": "test-admin", "password": "incorrect-password-44"}
    assert client.post("/api/v1/auth/login", json=data).status_code == 401
    with patch(
        "app.identity.check_password",
        side_effect=AssertionError("Rate limited request reached password hashing"),
    ):
        response = client.post("/api/v1/auth/login", json=data)
    assert response.status_code == 429
    assert int(response.headers["retry-after"]) > 0


def test_development_key_is_read_only_and_cannot_override_bad_bearer(managed, analyst_headers):
    _, _, client, _ = managed
    assert client.get("/api/v1/events", headers=analyst_headers).status_code == 200
    assert client.get("/api/v1/users", headers=analyst_headers).status_code == 403
    assert (
        client.get(
            "/api/v1/events", headers={**analyst_headers, "Authorization": "Bearer invalid"}
        ).status_code
        == 401
    )
    assert (
        client.get(
            "/api/v1/events", headers={**analyst_headers, "Authorization": "Basic invalid"}
        ).status_code
        == 401
    )


def test_user_pagination_and_assignment_directory(managed):
    _, _, client, users = managed
    first = client.get("/api/v1/users?limit=1", headers=users["admin"][1]).json()
    second = client.get(
        "/api/v1/users",
        params={"limit": 1, "after": first["next_cursor"]},
        headers=users["admin"][1],
    ).json()
    assert first["items"][0]["id"] != second["items"][0]["id"]
    directory = client.get("/api/v1/users/directory", headers=users["analyst"][1]).json()["items"]
    assert {row["role"] for row in directory} == {"admin", "analyst"}


def test_password_validation_does_not_echo_input(managed):
    _, _, client, _ = managed
    response = client.post(
        "/api/v1/auth/login", json={"username": "test-admin", "password": "secret"}
    )
    assert response.status_code == 422
    assert "secret" not in response.text


def test_user_deactivation_blocks_existing_session(managed):
    _, _, client, users = managed
    user, headers = users["viewer"]
    assert (
        client.patch(
            f"/api/v1/users/{user.id}",
            headers=users["admin"][1],
            json={"expected_revision": 0, "active": False},
        ).status_code
        == 200
    )
    assert client.get("/api/v1/events", headers=headers).status_code == 401
