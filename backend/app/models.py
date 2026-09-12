from datetime import UTC, datetime
from enum import StrEnum
from math import isfinite
from typing import Annotated, Literal
from uuid import UUID

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyAddress,
    JsonValue,
    field_validator,
    model_validator,
)

ShortText = Annotated[str, Field(min_length=1, max_length=255)]


class OperatingSystem(StrEnum):
    windows = "windows"
    macos = "macos"


class Severity(StrEnum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class EventType(StrEnum):
    login_success = "login_success"
    login_failure = "login_failure"
    logout = "logout"
    account_created = "account_created"
    account_deleted = "account_deleted"
    group_membership_changed = "group_membership_changed"
    privilege_assigned = "privilege_assigned"
    process_created = "process_created"
    service_installed = "service_installed"
    security_log_cleared = "security_log_cleared"
    ssh_login = "ssh_login"
    sudo_execution = "sudo_execution"
    firewall_event = "firewall_event"
    security_tool_event = "security_tool_event"
    other = "other"


class EventInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = 1
    event_uid: UUID
    endpoint_id: ShortText
    timestamp: AwareDatetime
    hostname: ShortText
    os: OperatingSystem
    source: ShortText
    event_type: EventType
    event_code: int | None = Field(default=None, ge=0, le=2**63 - 1)
    source_record_id: ShortText | None = None
    provider: ShortText | None = None
    collector_version: ShortText | None = None
    username: ShortText | None = None
    user_domain: ShortText | None = None
    user_sid: ShortText | None = None
    target_username: ShortText | None = None
    target_user_sid: ShortText | None = None
    group_name: ShortText | None = None
    group_sid: ShortText | None = None
    source_ip: IPvAnyAddress | None = None
    process_name: Annotated[str, Field(max_length=4096)] | None = None
    process_id: int | None = Field(default=None, ge=0, le=2**63 - 1)
    parent_process_name: Annotated[str, Field(max_length=4096)] | None = None
    parent_process_id: int | None = Field(default=None, ge=0, le=2**63 - 1)
    command_line: Annotated[str, Field(max_length=32768)] | None = None
    severity: Severity = Severity.info
    message: str = Field(max_length=32768)
    raw_event: dict[str, JsonValue] = Field(default_factory=dict)

    @field_validator("raw_event")
    @classmethod
    def bson_compatible_raw_event(cls, value: dict[str, JsonValue]) -> dict[str, JsonValue]:
        pending = [(value, 0)]
        while pending:
            item, depth = pending.pop()
            if depth > 32:
                raise ValueError("raw_event nesting must not exceed 32 levels")
            if isinstance(item, dict):
                if any("\u0000" in key for key in item):
                    raise ValueError("raw_event field names must not contain null bytes")
                pending.extend((child, depth + 1) for child in item.values())
            elif isinstance(item, list):
                pending.extend((child, depth + 1) for child in item)
            elif isinstance(item, int) and not -(2**63) <= item < 2**63:
                raise ValueError(
                    "raw_event integers must fit in signed 64 bits; encode larger IDs as strings"
                )
            elif isinstance(item, float) and not isfinite(item):
                raise ValueError("raw_event numbers must be finite")
        return value

    @field_validator("timestamp")
    @classmethod
    def canonical_timestamp(cls, value: datetime) -> datetime:
        # BSON datetime has millisecond precision. Normalize before hashing as well.
        value = value.astimezone(UTC)
        return value.replace(microsecond=(value.microsecond // 1000) * 1000)


class EventRecord(EventInput):
    id: str
    received_at: AwareDatetime


class IngestResult(BaseModel):
    event: EventRecord
    duplicate: bool


class EventPage(BaseModel):
    items: list[EventRecord]
    next_cursor: str | None


class EventFilters(BaseModel):
    model_config = ConfigDict(extra="forbid")

    endpoint_id: ShortText | None = None
    hostname: ShortText | None = None
    os: OperatingSystem | None = None
    event_type: EventType | None = None
    event_code: int | None = Field(default=None, ge=0, le=2**63 - 1)
    username: ShortText | None = None
    source_ip: IPvAnyAddress | None = None
    severity: Severity | None = None
    start_time: AwareDatetime | None = None
    end_time: AwareDatetime | None = None
    limit: int = Field(default=50, ge=1, le=200)
    cursor: str | None = Field(default=None, max_length=512)

    @model_validator(mode="after")
    def ordered_window(self) -> "EventFilters":
        if self.start_time and self.end_time and self.start_time > self.end_time:
            raise ValueError("start_time must not be after end_time")
        return self
