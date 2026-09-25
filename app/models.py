"""Shared domain models for the deterministic triage workflow."""

from datetime import datetime, timezone
from enum import Enum
from ipaddress import ip_address
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

SUPPORTED_EVENT_TYPES = {
    "ssh_login",
    "command_execution",
    "file_access",
    "privilege_escalation",
    "process_start",
    "web_request",
}
SUPPORTED_OUTCOMES = {"success", "failure", "info"}


class AuthenticationDetails(BaseModel):
    model_config = ConfigDict(extra="forbid")

    method: Literal["ssh"]


class WebRequestDetails(BaseModel):
    model_config = ConfigDict(extra="forbid")

    method: Literal["GET", "POST", "HEAD"]
    path: str = Field(min_length=1, pattern=r"^/")
    status_code: int = Field(ge=100, le=599)


class ProcessDetails(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: str = Field(min_length=1)


EventDetails = AuthenticationDetails | WebRequestDetails | ProcessDetails


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
    details: EventDetails | None = None

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

    @model_validator(mode="after")
    def validate_event_details(self) -> "SecurityEventInput":
        if self.event_type == "ssh_login":
            if self.details is not None and not isinstance(self.details, AuthenticationDetails):
                raise ValueError("ssh_login events require authentication details")
        elif self.event_type == "web_request":
            if not isinstance(self.details, WebRequestDetails):
                raise ValueError("web_request events require web request details")
        elif not isinstance(self.details, ProcessDetails):
            raise ValueError(f"{self.event_type} events require process details")
        return self


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


class InvestigationStatus(str, Enum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"


class InvestigationOutcome(str, Enum):
    TRUE_POSITIVE = "TRUE_POSITIVE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    BENIGN = "BENIGN"
    INCONCLUSIVE = "INCONCLUSIVE"


class EvidenceItem(BaseModel):
    model_config = ConfigDict(frozen=True)

    timestamp: datetime
    event_id: str
    host: str
    source_ip: str | None = None
    username: str | None = None
    event_type: str
    outcome: str
    details: EventDetails | None = None
    summary: str


class TimelineEntry(EvidenceItem):
    """Chronological analyst-facing representation of an evidence event."""


class Investigation(BaseModel):
    model_config = ConfigDict(validate_assignment=True)

    investigation_id: str
    created_at: datetime
    alerts: list[Alert]
    correlated_event_ids: list[str]
    evidence: list[EvidenceItem]
    timeline: list[TimelineEntry]
    status: InvestigationStatus = InvestigationStatus.OPEN
    outcome: InvestigationOutcome | None = None

    def __setattr__(self, name: str, value: object) -> None:
        """Rollback lifecycle fields if cross-field assignment validation fails."""
        if name not in {"status", "outcome"} or not hasattr(self, "status"):
            super().__setattr__(name, value)
            return
        previous_status = self.status
        previous_outcome = self.outcome
        try:
            super().__setattr__(name, value)
        except ValidationError:
            object.__setattr__(self, "status", previous_status)
            object.__setattr__(self, "outcome", previous_outcome)
            raise

    @model_validator(mode="after")
    def validate_status_outcome(self) -> "Investigation":
        if self.status == InvestigationStatus.RESOLVED and self.outcome is None:
            raise ValueError("resolved investigations require an outcome")
        if self.status != InvestigationStatus.RESOLVED and self.outcome is not None:
            raise ValueError("an outcome is allowed only when an investigation is resolved")
        return self


class AlertCorrelation(BaseModel):
    """The explicit correlation relationship retained for one alert."""

    alert: Alert
    correlated_event_ids: list[str]


class InvestigationBatch(BaseModel):
    investigations: list[Investigation]

    @property
    def alerts(self) -> list[Alert]:
        """Compatibility view for callers that previously consumed one batch result."""
        rule_order = {"THR-DET-001": 0, "THR-DET-003": 1, "THR-DET-002": 2, "THR-DET-004": 3}
        return sorted(
            [alert for investigation in self.investigations for alert in investigation.alerts],
            key=lambda alert: (rule_order.get(alert.detection.rule_id, len(rule_order)), alert.alert_id),
        )

    @property
    def correlated_event_ids(self) -> list[str]:
        return sorted(
            {
                event_id
                for investigation in self.investigations
                for event_id in investigation.correlated_event_ids
            }
        )

    @property
    def timeline(self) -> list[TimelineEntry]:
        return sorted(
            [entry for investigation in self.investigations for entry in investigation.timeline],
            key=lambda entry: (entry.timestamp, entry.event_id),
        )
