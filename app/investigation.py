"""Build a concise chronological investigation view."""

from .models import SecurityEvent, TimelineEntry


def build_timeline(events: list[SecurityEvent]) -> list[TimelineEntry]:
    return [
        TimelineEntry(
            timestamp=event.timestamp,
            event_id=event.event_id,
            event_type=event.event_type,
            outcome=event.outcome,
            summary=f"{event.event_type} {event.outcome} on {event.host}",
        )
        for event in sorted(events, key=lambda item: item.timestamp)
    ]
