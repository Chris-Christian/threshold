"""Detect a documented, intentionally small set of suspicious post-auth actions."""

from datetime import timedelta

from app.models import DetectionMatch, ProcessDetails, SecurityEvent

from .ssh_success_after_bruteforce import RULE_ID as SSH_SUCCESS_RULE_ID

RULE_ID = "THR-DET-004"
POST_AUTH_WINDOW = timedelta(minutes=15)
SUSPICIOUS_ACTIONS = frozenset({"download_tool", "add_user", "disable_logging"})


def detect_suspicious_post_auth_activity(
    events: list[SecurityEvent], successful_auth_matches: list[DetectionMatch]
) -> list[DetectionMatch]:
    """Re-validate events after a successful-auth candidate; matches are not evidence alone."""
    matches = []
    for auth_match in successful_auth_matches:
        if auth_match.rule_id != SSH_SUCCESS_RULE_ID:
            continue
        for event in sorted(events, key=lambda item: item.timestamp):
            if not (
                isinstance(event.details, ProcessDetails)
                and event.details.action in SUSPICIOUS_ACTIONS
                and event.source_ip == auth_match.source_ip
                and event.host == auth_match.host
                and event.username == auth_match.username
                and auth_match.window_end
                < event.timestamp
                <= auth_match.window_end + POST_AUTH_WINDOW
            ):
                continue
            matches.append(
                DetectionMatch(
                    rule_id=RULE_ID,
                    title="Suspicious post-authentication activity",
                    severity="critical",
                    event_ids=[auth_match.event_ids[-1], event.event_id],
                    source_ip=event.source_ip,
                    host=event.host,
                    username=event.username,
                    summary=(
                        f"Suspicious action '{event.details.action}' followed successful SSH "
                        f"authentication from {event.source_ip} to {event.host}"
                    ),
                    window_start=auth_match.window_end,
                    window_end=event.timestamp,
                )
            )
            break
    return matches
