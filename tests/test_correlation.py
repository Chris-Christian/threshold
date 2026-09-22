from app.correlation import correlate_events
from app.normalization import normalize_events
from detections.ssh_bruteforce import detect_ssh_brute_force
from simulator.linux_auth import ssh_brute_force_investigation_scenario


def test_ssh_correlation_includes_post_auth_activity_and_excludes_unrelated_events():
    events = normalize_events(ssh_brute_force_investigation_scenario())
    match = detect_ssh_brute_force(events)[0]

    correlated_ids = {event.event_id for event in correlate_events(events, match)}

    assert {"auth-success", "post-auth-command", "post-auth-file-access"} <= correlated_ids
    assert "other-host" not in correlated_ids
    assert "other-source" not in correlated_ids
    assert "irrelevant-event-type" not in correlated_ids
    assert "pre-auth-command" not in correlated_ids
    assert "outside-window" not in correlated_ids
