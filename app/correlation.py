"""Explicit, bounded correlation for deterministic Threshold investigations."""

from datetime import timedelta

from detections.web_reconnaissance import SENSITIVE_PATHS

from .models import DetectionMatch, ProcessDetails, SecurityEvent, WebRequestDetails

SSH_RULE_IDS = frozenset({"THR-DET-001", "THR-DET-002", "THR-DET-004"})
SSH_INVESTIGATION_LOOKAHEAD = timedelta(minutes=15)


def _correlate_ssh_events(events: list[SecurityEvent], match: DetectionMatch) -> list[SecurityEvent]:
    end = (
        match.window_end + SSH_INVESTIGATION_LOOKAHEAD
        if match.rule_id in {"THR-DET-001", "THR-DET-002"}
        else match.window_end
    )
    scoped = sorted(
        [
            event
            for event in events
            if (
                event.source_ip == match.source_ip
                and event.host == match.host
                and match.window_start <= event.timestamp <= end
                and (
                    event.event_type == "ssh_login"
                    or isinstance(event.details, ProcessDetails)
                )
            )
        ],
        key=lambda event: event.timestamp,
    )
    successful_auths = [
        (event.timestamp, event.username)
        for event in scoped
        if event.event_type == "ssh_login" and event.outcome == "success"
    ]
    return [
        event
        for event in scoped
        if event.event_type == "ssh_login"
        or (
            isinstance(event.details, ProcessDetails)
            and (match.username is None or event.username == match.username)
            and any(
                success_time <= event.timestamp and success_username == event.username
                for success_time, success_username in successful_auths
            )
        )
    ]


def _correlate_web_events(events: list[SecurityEvent], match: DetectionMatch) -> list[SecurityEvent]:
    return sorted(
        [
            event
            for event in events
            if (
                event.source_ip == match.source_ip
                and event.host == match.host
                and match.window_start <= event.timestamp <= match.window_end
                and event.event_type == "web_request"
                and isinstance(event.details, WebRequestDetails)
                and event.details.path in SENSITIVE_PATHS
            )
        ],
        key=lambda event: event.timestamp,
    )


def correlate_events(events: list[SecurityEvent], match: DetectionMatch) -> list[SecurityEvent]:
    """Correlate only events that independently satisfy the rule's scope."""
    if match.rule_id in SSH_RULE_IDS:
        return _correlate_ssh_events(events, match)
    if match.rule_id == "THR-DET-003":
        return _correlate_web_events(events, match)
    return []
