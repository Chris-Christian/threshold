"""Detect deterministic probing of a small set of sensitive web paths."""

from collections import defaultdict
from datetime import timedelta

from app.models import DetectionMatch, SecurityEvent, WebRequestDetails

RULE_ID = "THR-DET-003"
SENSITIVE_PATHS = frozenset({"/.env", "/.git/config", "/wp-admin", "/phpmyadmin"})
DISTINCT_PATH_THRESHOLD = 3
WINDOW = timedelta(minutes=5)


def detect_web_reconnaissance(events: list[SecurityEvent]) -> list[DetectionMatch]:
    groups: dict[tuple[str, str], list[SecurityEvent]] = defaultdict(list)
    for event in events:
        if (
            event.event_type == "web_request"
            and event.source_ip
            and isinstance(event.details, WebRequestDetails)
            and event.details.path in SENSITIVE_PATHS
        ):
            groups[(event.host, event.source_ip)].append(event)

    matches = []
    for (host, source_ip), requests in groups.items():
        requests.sort(key=lambda event: event.timestamp)
        for start, first_request in enumerate(requests):
            window_requests = [
                event
                for event in requests[start:]
                if event.timestamp - first_request.timestamp <= WINDOW
            ]
            paths = {event.details.path for event in window_requests if isinstance(event.details, WebRequestDetails)}
            if len(paths) >= DISTINCT_PATH_THRESHOLD:
                matches.append(
                    DetectionMatch(
                        rule_id=RULE_ID,
                        title="Web reconnaissance against sensitive paths",
                        severity="medium",
                        event_ids=[event.event_id for event in window_requests],
                        source_ip=source_ip,
                        host=host,
                        summary=(
                            f"{len(paths)} sensitive paths probed by {source_ip} against {host} "
                            "within five minutes"
                        ),
                        window_start=window_requests[0].timestamp,
                        window_end=window_requests[-1].timestamp,
                    )
                )
                break
    return matches
