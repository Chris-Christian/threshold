"""Rule-based SSH brute-force detection; intentionally independent of AI systems."""

from collections import defaultdict
from datetime import timedelta

from app.models import DetectionMatch, SecurityEvent

RULE_ID = "SSH_BRUTE_FORCE"
FAILED_SSH_LOGIN = "ssh_login"
FAILURE_THRESHOLD = 5
WINDOW = timedelta(minutes=5)


def detect_ssh_brute_force(events: list[SecurityEvent]) -> list[DetectionMatch]:
    groups: dict[tuple[str, str], list[SecurityEvent]] = defaultdict(list)
    for event in events:
        if event.event_type == FAILED_SSH_LOGIN and event.outcome == "failure" and event.source_ip:
            groups[(event.host, event.source_ip)].append(event)

    matches = []
    for (host, source_ip), attempts in groups.items():
        attempts.sort(key=lambda event: event.timestamp)
        for start in range(len(attempts)):
            window_attempts = [
                event for event in attempts[start:]
                if event.timestamp - attempts[start].timestamp <= WINDOW
            ]
            if len(window_attempts) >= FAILURE_THRESHOLD:
                matches.append(
                    DetectionMatch(
                        rule_id=RULE_ID,
                        title="SSH brute-force activity",
                        severity="high",
                        event_ids=[event.event_id for event in window_attempts],
                        source_ip=source_ip,
                        host=host,
                        summary=(
                            f"{len(window_attempts)} failed SSH logins from {source_ip} "
                            f"against {host} within five minutes"
                        ),
                        window_start=window_attempts[0].timestamp,
                        window_end=window_attempts[-1].timestamp,
                    )
                )
                break
    return matches
