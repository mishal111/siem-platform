import os
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]


class ConfigurationError(Exception):
    pass


@dataclass(frozen=True)
class Config:
    api_url: str = "http://127.0.0.1:8000/api/v1/events"
    api_key: str = field(default="", repr=False)
    state_dir: Path = ROOT / ".local" / "collector"
    poll_seconds: float = 5.0
    request_timeout: float = 5.0
    batch_size: int = 20
    max_events: int = 10000
    max_bytes: int = 16 * 1024 * 1024
    lookback_seconds: int = 60
    window_seconds: int = 30
    overlap_seconds: int = 5
    settle_seconds: int = 3

    def validate(self, require_key=True):
        url = urlsplit(self.api_url)
        if url.scheme not in ("http", "https") or not url.hostname or url.username or url.password:
            raise ConfigurationError(
                "Collector API URL must be HTTP(S), without embedded credentials"
            )
        if url.query or url.fragment or not url.path.endswith("/api/v1/events"):
            raise ConfigurationError(
                "Collector API URL must end in /api/v1/events without query/fragment"
            )
        if url.scheme == "http" and url.hostname not in ("127.0.0.1", "::1", "localhost"):
            raise ConfigurationError(
                "HTTP is allowed only on loopback; remote collectors require HTTPS"
            )
        if require_key and (
            len(self.api_key) < 32
            or not self.api_key.isascii()
            or any(char.isspace() for char in self.api_key)
            or self.api_key.startswith(("replace-", "change-me"))
        ):
            raise ConfigurationError("Set a valid SIEM_API_KEY or COLLECTOR_API_KEY")
        if not 0.1 <= self.poll_seconds <= 300 or not 0.1 <= self.request_timeout <= 60:
            raise ConfigurationError("Poll/timeout settings are outside their supported range")
        if not 1 <= self.batch_size <= 200 or not 1 <= self.max_events <= 100000:
            raise ConfigurationError("Batch size or queue limit is outside its supported range")
        if not 1024 <= self.max_bytes <= 1024 * 1024 * 1024:
            raise ConfigurationError("Queue byte limit must be between 1 KiB and 1 GiB")
        if not 0 <= self.lookback_seconds <= 86400:
            raise ConfigurationError("Initial lookback must be between 0 and 86400 seconds")
        return self


def load_config(env_file=ROOT / ".env", require_key=True):
    values = {}
    path = Path(env_file)
    if path.exists():
        for line in path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                values[key.strip()] = value.strip().strip("\"'")
    # Environment variables override the simple KEY=VALUE development env file.
    values.update(os.environ)
    try:
        return Config(
            api_url=values.get("SIEM_API_URL", Config.api_url),
            api_key=values.get("SIEM_API_KEY", values.get("COLLECTOR_API_KEY", "")),
            state_dir=Path(values.get("COLLECTOR_STATE_DIR", str(Config.state_dir))).expanduser(),
            poll_seconds=float(values.get("COLLECTOR_POLL_SECONDS", "5")),
            request_timeout=float(values.get("COLLECTOR_REQUEST_TIMEOUT", "5")),
            batch_size=int(values.get("COLLECTOR_BATCH_SIZE", "20")),
            max_events=int(values.get("COLLECTOR_MAX_EVENTS", "10000")),
            max_bytes=int(values.get("COLLECTOR_MAX_BYTES", str(16 * 1024 * 1024))),
            lookback_seconds=int(values.get("COLLECTOR_LOOKBACK_SECONDS", "60")),
        ).validate(require_key=require_key)
    except (ValueError, OSError) as exc:
        raise ConfigurationError("Invalid collector configuration") from exc
