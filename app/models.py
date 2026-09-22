"""Shared domain models for the deterministic triage workflow."""

from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

SUPPORTED_EVENT_TYPES = {
    "ssh_login",
    "command_execution",
    "file_access",
    "privilege_escalation",
    "process_start",
}
SUPPORTED_OUTCOMES = {"success", "failure", "info"}


class SecurityEventInput(BaseModel):
    """Validated inbound event; timestamps are converted to UTC."""

    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(min_length=1)
    timestamp: datetime
    host: str = Field(min_length=1)
    event_type: str
    outcome: str
    username: str | None = Field(default=None, min_length=1)
    source_ip: str | None = None

    @field_validator("timestamp")
    @classmethod
    def require_timezone_and_normalize_to_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must be timezone-aware")
        return value.astimezone(timezone.utc)

    @field_validator("source_ip")
    @classmethod
    def validate_source_ip(cls, value: str | None) -> str | None:
        if value is not None:
            ip_address(value)
        return value

    @field_validator("event_type")
    @classmethod
    def validate_event_type(cls, value: str) -> str:
        if value not in SUPPORTED_EVENT_TYPES:
            raise ValueError(f"unsupported event_type: {value}")
        return value

    @field_validator("outcome")
    @classmethod
    def validate_outcome(cls, value: str) -> str:
        if value not in SUPPORTED_OUTCOMES:
            raise ValueError(f"unsupported outcome: {value}")
        return value


class SecurityEvent(SecurityEventInput):
    """Normalized event retained by the deterministic workflow."""

    raw: dict[str, Any] = Field(default_factory=dict)


class DetectionMatch(BaseModel):
    rule_id: str
    title: str
    severity: str
    event_ids: list[str]
    source_ip: str | None = None
    host: str | None = None
    username: str | None = None
    summary: str
    window_start: datetime
    window_end: datetime


class Alert(BaseModel):
    alert_id: str
    detection: DetectionMatch


class TimelineEntry(BaseModel):
    timestamp: datetime
    event_id: str
    event_type: str
    outcome: str
    summary: str


class Investigation(BaseModel):
    alerts: list[Alert]
    correlated_event_ids: list[str]
    timeline: list[TimelineEntry]
