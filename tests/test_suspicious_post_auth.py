from app.normalization import normalize_events
from app.workflow import run_detections
from simulator.linux_auth import (
    benign_ssh_activity_scenario,
    ssh_brute_force_followed_by_success_scenario,
    ssh_brute_force_success_suspicious_activity_scenario,
)


def post_auth_matches(events: list[dict]):
    return [match for match in run_detections(normalize_events(events)) if match.rule_id == "THR-DET-004"]


def test_detects_documented_suspicious_action_after_successful_ssh_authentication():
    matches = post_auth_matches(ssh_brute_force_success_suspicious_activity_scenario())

    assert len(matches) == 1
    assert matches[0].event_ids[-1] == "post-auth-download"


def test_ignores_benign_ssh_and_non_suspicious_post_auth_action():
    events = ssh_brute_force_followed_by_success_scenario() + [
        {
            "event_id": "benign-command",
            "timestamp": "2026-01-01T12:06:00+00:00",
            "host": "web-01",
            "event_type": "command_execution",
            "outcome": "success",
            "username": "root",
            "source_ip": "203.0.113.10",
            "details": {"action": "list_files"},
        }
    ]

    assert post_auth_matches(benign_ssh_activity_scenario()) == []
    assert post_auth_matches(events) == []


def test_accepts_exact_post_auth_window_boundary_and_excludes_outside_or_wrong_scope():
    base = ssh_brute_force_success_suspicious_activity_scenario()
    base[-1]["timestamp"] = "2026-01-01T12:20:00+00:00"
    assert len(post_auth_matches(base)) == 1

    for field, value in (("timestamp", "2026-01-01T12:20:01+00:00"), ("host", "db-01"), ("source_ip", "198.51.100.5"), ("username", "deploy")):
        events = ssh_brute_force_success_suspicious_activity_scenario()
        events[-1][field] = value
        assert post_auth_matches(events) == []
