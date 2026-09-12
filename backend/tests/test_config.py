import pytest
from pydantic import ValidationError

from app.config import Settings


@pytest.mark.parametrize("key", ["short", "change-me" + "x" * 40, "replace-" + "x" * 40, " " * 40])
def test_reject_placeholder_or_weak_keys(key):
    with pytest.raises(ValidationError):
        Settings(_env_file=None, collector_api_key=key, analyst_api_key="a" * 40)


def test_reject_same_key():
    with pytest.raises(ValidationError, match="must be different"):
        Settings(_env_file=None, collector_api_key="a" * 40, analyst_api_key="a" * 40)


def test_hardened_settings_require_mongo_auth_and_disable_legacy():
    valid = {
        "_env_file": None,
        "deployment_mode": "hardened",
        "allow_legacy_keys": False,
        "mongo_uri": "mongodb://app:test-password@mongodb/siem",
    }
    assert Settings(**valid).allow_legacy_keys is False
    for changes in (
        {"allow_legacy_keys": True},
        {"mongo_uri": "mongodb://mongodb/siem"},
        {"cors_origins": ["http://example.com"]},
        {"allowed_hosts": ["*"]},
    ):
        with pytest.raises(ValidationError):
            Settings(**{**valid, **changes})


def test_cors_rejects_wildcard_paths_and_embedded_credentials():
    for origin in ("*", "https://example.com/path", "https://user:password@example.com"):
        with pytest.raises(ValidationError):
            Settings(_env_file=None, allow_legacy_keys=False, cors_origins=[origin])
