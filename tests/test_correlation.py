from app.correlation import correlate_events
from app.normalization import normalize_events
from app.workflow import run_detections
from detections.web_reconnaissance import detect_web_reconnaissance
from simulator.linux_auth import ssh_brute_force_investigation_scenario
from simulator.linux_auth import web_reconnaissance_scenario


def test_ssh_correlation_includes_post_auth_activity_and_excludes_unrelated_events():
    events = normalize_events(ssh_brute_force_investigation_scenario())
    match = run_detections(events)[0]

    correlated_ids = {event.event_id for event in correlate_events(events, match)}

    assert {"auth-success", "post-auth-download"} <= correlated_ids
    assert "other-host-action" not in correlated_ids
    assert "other-ip-action" not in correlated_ids
    assert "other-user-action" not in correlated_ids
    assert "outside-window-action" not in correlated_ids


def test_web_correlation_excludes_same_ip_noise_and_other_host_requests():
    raw_events = web_reconnaissance_scenario() + [
        {
            "event_id": "same-ip-benign-path",
            "timestamp": "2026-01-01T12:01:00+00:00",
            "host": "web-01",
            "event_type": "web_request",
            "outcome": "success",
            "source_ip": "203.0.113.10",
            "details": {"method": "GET", "path": "/", "status_code": 200},
        },
        {
            "event_id": "other-host-sensitive-path",
            "timestamp": "2026-01-01T12:01:00+00:00",
            "host": "db-01",
            "event_type": "web_request",
            "outcome": "failure",
            "source_ip": "203.0.113.10",
            "details": {"method": "GET", "path": "/.env", "status_code": 404},
        },
    ]
    events = normalize_events(raw_events)
    match = detect_web_reconnaissance(events)[0]

    correlated_ids = {event.event_id for event in correlate_events(events, match)}

    assert correlated_ids == {"web-recon-0", "web-recon-1", "web-recon-2"}
