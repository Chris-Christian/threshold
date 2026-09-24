from datetime import timedelta

from app.normalization import normalize_events
from detections.ssh_bruteforce import detect_ssh_brute_force
from detections.ssh_success_after_bruteforce import detect_ssh_success_after_bruteforce
from simulator.linux_auth import ssh_brute_force_followed_by_success_scenario, ssh_brute_force_only_scenario


def _matches(events: list[dict]):
    normalized = normalize_events(events)
    brute_force = detect_ssh_brute_force(normalized)
    return detect_ssh_success_after_bruteforce(normalized, brute_force)


def test_detects_successful_ssh_authentication_after_brute_force():
    matches = _matches(ssh_brute_force_followed_by_success_scenario())

    assert len(matches) == 1
    assert matches[0].rule_id == "THR-DET-002"
    assert matches[0].event_ids[-1] == "auth-success"


def test_does_not_detect_success_without_a_prior_brute_force_match():
    assert _matches(ssh_brute_force_only_scenario()[:4] + ssh_brute_force_followed_by_success_scenario()[-1:]) == []


def test_detects_success_at_exact_fifteen_minute_boundary():
    events = ssh_brute_force_followed_by_success_scenario()
    events[-1]["timestamp"] = "2026-01-01T12:19:00+00:00"

    assert len(_matches(events)) == 1


def test_excludes_success_outside_fifteen_minute_boundary():
    events = ssh_brute_force_followed_by_success_scenario()
    events[-1]["timestamp"] = "2026-01-01T12:19:01+00:00"

    assert _matches(events) == []


def test_excludes_success_on_another_host_or_source_ip():
    for field, value in (("host", "db-01"), ("source_ip", "198.51.100.5")):
        events = ssh_brute_force_followed_by_success_scenario()
        events[-1][field] = value
        assert _matches(events) == []
