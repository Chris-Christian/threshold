from datetime import datetime, timedelta, timezone

from app.normalization import normalize_events
from detections.web_reconnaissance import detect_web_reconnaissance
from simulator.linux_auth import benign_web_browsing_scenario, web_reconnaissance_scenario


def web_event(event_id: str, minute: int, path: str, *, source_ip: str = "203.0.113.10", host: str = "web-01") -> dict:
    start = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    return {
        "event_id": event_id,
        "timestamp": (start + timedelta(minutes=minute)).isoformat(),
        "host": host,
        "event_type": "web_request",
        "outcome": "failure",
        "source_ip": source_ip,
        "details": {"method": "GET", "path": path, "status_code": 404},
    }


def test_detects_three_distinct_sensitive_path_probes():
    matches = detect_web_reconnaissance(normalize_events(web_reconnaissance_scenario()))

    assert len(matches) == 1
    assert matches[0].rule_id == "THR-DET-003"


def test_ignores_benign_web_browsing_and_repeated_single_path():
    repeated = [web_event(f"repeat-{index}", index, "/.env") for index in range(3)]

    assert detect_web_reconnaissance(normalize_events(benign_web_browsing_scenario())) == []
    assert detect_web_reconnaissance(normalize_events(repeated)) == []


def test_requires_three_distinct_paths_and_accepts_exact_window_boundary():
    two_paths = [web_event("one", 0, "/.env"), web_event("two", 1, "/.git/config")]
    boundary = two_paths + [web_event("three", 5, "/wp-admin")]

    assert detect_web_reconnaissance(normalize_events(two_paths)) == []
    assert len(detect_web_reconnaissance(normalize_events(boundary))) == 1


def test_excludes_paths_outside_window_and_keeps_source_host_scopes_isolated():
    outside = [
        web_event("one", 0, "/.env"),
        web_event("two", 1, "/.git/config"),
        web_event("three", 6, "/wp-admin"),
    ]
    split = [
        web_event("one", 0, "/.env"),
        web_event("two", 1, "/.git/config", source_ip="198.51.100.5"),
        web_event("three", 2, "/wp-admin", host="db-01"),
    ]

    assert detect_web_reconnaissance(normalize_events(outside)) == []
    assert detect_web_reconnaissance(normalize_events(split)) == []
