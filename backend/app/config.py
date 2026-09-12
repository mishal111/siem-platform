import os
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", hide_input_in_errors=True)

    mongo_uri: SecretStr = SecretStr("mongodb://127.0.0.1:27017")
    mongo_db: str = Field(default="siem", pattern=r"^[A-Za-z0-9_-]{1,63}$")
    collector_api_key: SecretStr | None = None
    analyst_api_key: SecretStr | None = None
    allow_legacy_keys: bool = True
    deployment_mode: Literal["development", "hardened"] = "development"
    allowed_hosts: list[str] = Field(
        default_factory=lambda: ["localhost", "127.0.0.1", "testserver"]
    )
    session_hours: int = Field(default=8, ge=1, le=24)
    login_user_attempts: int = Field(default=10, ge=1, le=100)
    login_peer_attempts: int = Field(default=30, ge=1, le=1000)
    requests_per_minute: int = Field(default=6000, ge=10, le=100000)
    max_concurrent_requests: int = Field(default=100, ge=1, le=1000)
    request_body_timeout_seconds: float = Field(default=10, ge=0.1, le=60)
    cors_origins: list[str] = Field(default_factory=list)
    max_request_bytes: int = Field(default=1_048_576, ge=1024, le=10_485_760)
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    detection_poll_seconds: float = Field(default=1.0, ge=0.1, le=30)
    detection_lease_seconds: int = Field(default=60, ge=15, le=300)
    detection_max_attempts: int = Field(default=5, ge=1, le=20)
    detection_max_lateness_seconds: int = Field(default=86400, ge=600, le=604800)
    detection_future_skew_seconds: int = Field(default=120, ge=0, le=600)

    @field_validator("collector_api_key", "analyst_api_key")
    @classmethod
    def validate_key(cls, value: SecretStr | None) -> SecretStr | None:
        if value is None:
            return value
        key = value.get_secret_value()
        if len(key) < 32 or not key.isascii() or key.startswith(("replace-", "change-me")):
            raise ValueError(
                "API keys must be non-placeholder ASCII secrets of at least 32 characters"
            )
        if any(character.isspace() for character in key):
            raise ValueError("API keys must not contain whitespace")
        return value

    @model_validator(mode="after")
    def separate_keys(self) -> "Settings":
        if self.allow_legacy_keys and (not self.collector_api_key or not self.analyst_api_key):
            raise ValueError("Development keys are required while legacy authentication is enabled")
        if self.collector_api_key and self.collector_api_key == self.analyst_api_key:
            raise ValueError("Collector and analyst API keys must be different")
        if not self.allowed_hosts or any("*" in host for host in self.allowed_hosts):
            raise ValueError("Explicit allowed hostnames are required")
        for origin in self.cors_origins:
            parsed = urlsplit(origin)
            if (
                parsed.scheme not in ("http", "https")
                or not parsed.hostname
                or parsed.username
                or parsed.password
                or parsed.path
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError("CORS entries must be exact HTTP(S) origins without paths")
        if self.deployment_mode == "hardened":
            if self.allow_legacy_keys:
                raise ValueError("Hardened deployments require user sessions and endpoint keys")
            if not urlsplit(self.mongo_uri.get_secret_value()).username:
                raise ValueError("Hardened deployments require authenticated MongoDB")
            if any(not origin.startswith("https://") for origin in self.cors_origins):
                raise ValueError("Hardened deployments require HTTPS browser origins")
        return self

    def __init__(self, **values):
        if "_secrets_dir" not in values and os.environ.get("SIEM_SECRETS_DIR"):
            values["_secrets_dir"] = os.environ["SIEM_SECRETS_DIR"]
        super().__init__(**values)
