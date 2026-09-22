from datetime import datetime, timedelta, timezone

import pytest

from app.normalization import normalize_events
from detections.ssh_bruteforce import detect_ssh_brute_force


def failed_logins(
    count: int,
    *,
    source_ip: str = "203.0.113.10",
    host: str = "web-01",
    interval_seconds: int = 60,
) -> list[dict]:
    start = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    return [
        {
            "event_id": f"{host}-{source_ip}-{index}",
            "timestamp": (start + timedelta(seconds=index * interval_seconds)).isoformat(),
            "host": host,
            "event_type": "ssh_login",
            "outcome": "failure",
            "source_ip": source_ip,
        }
        for index in range(count)
    ]


@pytest.mark.parametrize("count, expected_matches", [(4, 0), (5, 1), (6, 1)])
def test_failure_thresholds(count: int, expected_matches: int):
    matches = detect_ssh_brute_force(normalize_events(failed_logins(count)))

    assert len(matches) == expected_matches
    if matches:
        assert len(matches[0].event_ids) == count


def test_does_not_detect_failures_outside_five_minute_window():
    matches = detect_ssh_brute_force(normalize_events(failed_logins(5, interval_seconds=76)))

    assert matches == []


def test_detects_failures_at_exact_five_minute_boundary():
    matches = detect_ssh_brute_force(normalize_events(failed_logins(5, interval_seconds=75)))

    assert len(matches) == 1


def test_keeps_multiple_source_ips_separate():
    events = failed_logins(4, source_ip="203.0.113.10") + failed_logins(
        4, source_ip="198.51.100.5"
    )

    assert detect_ssh_brute_force(normalize_events(events)) == []


def test_keeps_multiple_hosts_separate():
    events = failed_logins(4, host="web-01") + failed_logins(4, host="db-01")

    assert detect_ssh_brute_force(normalize_events(events)) == []


def test_ignores_successful_authentication_mixed_with_failures():
    events = failed_logins(5)
    events.append(
        {
            "event_id": "successful-login",
            "timestamp": "2026-01-01T12:02:30+00:00",
            "host": "web-01",
            "event_type": "ssh_login",
            "outcome": "success",
            "source_ip": "203.0.113.10",
        }
    )

    matches = detect_ssh_brute_force(normalize_events(events))

    assert len(matches) == 1
    assert len(matches[0].event_ids) == 5
    assert "successful-login" not in matches[0].event_ids
