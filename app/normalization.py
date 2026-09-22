"""Convert simulator or future collector payloads into one event shape."""

from collections.abc import Iterable
from typing import Any

from .models import SecurityEvent, SecurityEventInput


def normalize_event(raw_event: dict[str, Any] | SecurityEventInput) -> SecurityEvent:
    """Validate a payload and retain its JSON-safe source representation."""
    validated = (
        raw_event
        if isinstance(raw_event, SecurityEventInput)
        else SecurityEventInput.model_validate(raw_event)
    )
    return SecurityEvent(
        **validated.model_dump(),
        raw=validated.model_dump(mode="json"),
    )


def normalize_events(
    raw_events: Iterable[dict[str, Any] | SecurityEventInput],
) -> list[SecurityEvent]:
    return [normalize_event(event) for event in raw_events]
