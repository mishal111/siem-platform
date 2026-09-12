import pytest
from fastapi.testclient import TestClient

from app.main import create_app


def test_hardened_mode_requires_https_and_hides_public_docs(settings, repository):
    settings.deployment_mode = "hardened"
    settings.allow_legacy_keys = False
    with TestClient(create_app(settings, repository)) as client:
        assert client.get("/api/v1/health").status_code == 200
        assert client.get("/api/v1/events").status_code == 400
        assert (
            client.get("/api/v1/events", headers={"X-Forwarded-Proto": "https"}).status_code == 400
        )
        assert client.get("https://testserver/api/v1/events").status_code == 401
        assert client.get("https://testserver/openapi.json").status_code == 404
        assert client.get("https://testserver/docs").status_code == 404


def test_unapproved_host_is_rejected(client):
    assert client.get("/api/v1/health", headers={"Host": "attacker.invalid"}).status_code == 400


def test_cors_allows_configured_authorization_and_patch_only(settings, repository):
    settings.cors_origins = ["http://localhost:5173"]
    with TestClient(create_app(settings, repository)) as client:
        headers = {
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "PATCH",
            "Access-Control-Request-Headers": "authorization,content-type",
        }
        result = client.options("/api/v1/alerts/test", headers=headers)
        assert result.status_code == 200
        assert result.headers["access-control-allow-origin"] == headers["Origin"]
        assert (
            client.options(
                "/api/v1/alerts/test", headers={**headers, "Origin": "http://attacker.invalid"}
            ).status_code
            == 400
        )


def test_secrets_directory_loads_mongo_uri_without_public_keys(tmp_path, monkeypatch):
    from app.config import Settings

    (tmp_path / "mongo_uri").write_text("mongodb://app:synthetic-password@mongodb/siem")
    monkeypatch.setenv("SIEM_SECRETS_DIR", str(tmp_path))
    settings = Settings(_env_file=None, deployment_mode="hardened", allow_legacy_keys=False)
    assert settings.mongo_uri.get_secret_value().startswith("mongodb://app:")
    assert "synthetic-password" not in repr(settings)


@pytest.mark.integration
def test_account_history_limit_cannot_be_bypassed_by_future_revision(managed):
    _, repo, client, users = managed
    user, _ = users["analyst"]
    result = client.patch(
        f"/api/v1/users/{user.id}",
        headers=users["admin"][1],
        json={"expected_revision": 1, "role": "admin"},
    )
    assert result.status_code == 409
    assert repo.identity.users.find_one({"_id": user.id})["role"] == "analyst"
