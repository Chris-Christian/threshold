"""Detect successful SSH authentication following a brute-force match."""

from datetime import timedelta

from app.models import DetectionMatch, SecurityEvent

from .ssh_bruteforce import RULE_ID as SSH_BRUTE_FORCE_RULE_ID

RULE_ID = "THR-DET-002"
AUTH_SUCCESS_LOOKAHEAD = timedelta(minutes=15)


def detect_ssh_success_after_bruteforce(
    events: list[SecurityEvent], brute_force_matches: list[DetectionMatch]
) -> list[DetectionMatch]:
    """Re-validate source, host, time, and SSH success against each candidate match."""
    matches = []
    for brute_force in brute_force_matches:
        if brute_force.rule_id != SSH_BRUTE_FORCE_RULE_ID:
            continue
        for event in sorted(events, key=lambda item: item.timestamp):
            if not (
                event.event_type == "ssh_login"
                and event.outcome == "success"
                and event.source_ip == brute_force.source_ip
                and event.host == brute_force.host
                and brute_force.window_end
                < event.timestamp
                <= brute_force.window_end + AUTH_SUCCESS_LOOKAHEAD
            ):
                continue
            matches.append(
                DetectionMatch(
                    rule_id=RULE_ID,
                    title="SSH brute force followed by successful authentication",
                    severity="critical",
                    event_ids=[*brute_force.event_ids, event.event_id],
                    source_ip=event.source_ip,
                    host=event.host,
                    username=event.username,
                    summary=(
                        f"Successful SSH authentication from {event.source_ip} to {event.host} "
                        "followed a detected brute-force window"
                    ),
                    window_start=brute_force.window_start,
                    window_end=event.timestamp,
                )
            )
            break
    return matches
