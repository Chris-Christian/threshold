"""Deterministic correlation for SSH investigations."""

from datetime import timedelta

from .models import DetectionMatch, SecurityEvent

INVESTIGATION_LOOKAHEAD = timedelta(minutes=15)
SSH_INVESTIGATION_EVENT_TYPES = {
    "ssh_login",
    "command_execution",
    "file_access",
    "privilege_escalation",
}
POST_AUTH_EVENT_TYPES = {
    "command_execution",
    "file_access",
    "privilege_escalation",
}


def correlate_events(events: list[SecurityEvent], match: DetectionMatch) -> list[SecurityEvent]:
    """Scope SSH activity by source, host, relevance, and bounded time range."""
    correlation_end = match.window_end + INVESTIGATION_LOOKAHEAD
    scoped_events = sorted(
        [
            event
            for event in events
            if (
                event.source_ip == match.source_ip
                and event.host == match.host
                and match.window_start <= event.timestamp <= correlation_end
                and event.event_type in SSH_INVESTIGATION_EVENT_TYPES
            )
        ],
        key=lambda event: event.timestamp,
    )
    successful_auth_times = [
        event.timestamp
        for event in scoped_events
        if event.event_type == "ssh_login" and event.outcome == "success"
    ]
    return [
        event
        for event in scoped_events
        if (
            event.event_type == "ssh_login"
            or (
                event.event_type in POST_AUTH_EVENT_TYPES
                and any(success_time <= event.timestamp for success_time in successful_auth_times)
            )
        )
    ]
