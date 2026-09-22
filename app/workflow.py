"""Orchestrate normalization, rule execution, correlation, and timeline assembly."""

from uuid import uuid4

from detections.ssh_bruteforce import detect_ssh_brute_force

from .correlation import correlate_events
from .investigation import build_timeline
from .models import Alert, Investigation
from .normalization import normalize_events


def triage(raw_events: list[dict]) -> Investigation:
    events = normalize_events(raw_events)
    matches = detect_ssh_brute_force(events)
    alerts = [Alert(alert_id=str(uuid4()), detection=match) for match in matches]

    correlated = {
        event.event_id
        for match in matches
        for event in correlate_events(events, match)
    }
    related_events = [event for event in events if event.event_id in correlated]
    return Investigation(
        alerts=alerts,
        correlated_event_ids=sorted(correlated),
        timeline=build_timeline(related_events),
    )
