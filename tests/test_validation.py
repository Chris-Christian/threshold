import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.main import app
from app.normalization import normalize_event


def valid_event() -> dict:
    return {
        "event_id": "event-1",
        "timestamp": "2026-01-01T12:00:00+05:30",
        "host": "web-01",
        "event_type": "ssh_login",
        "outcome": "failure",
        "source_ip": "203.0.113.10",
    }


def test_normalization_requires_timezone_aware_timestamp():
    event = valid_event()
    event["timestamp"] = "2026-01-01T12:00:00"

    with pytest.raises(ValidationError, match="timezone-aware"):
        normalize_event(event)


def test_normalization_converts_timestamp_to_utc():
    normalized = normalize_event(valid_event())

    assert normalized.timestamp.isoformat() == "2026-01-01T06:30:00+00:00"


def test_api_returns_422_for_malformed_event():
    malformed = valid_event()
    del malformed["host"]

    response = TestClient(app).post("/investigations", json={"events": [malformed]})

    assert response.status_code == 422
