"""Deterministic V0.2 security-event scenarios for Threshold tests and demos."""

from datetime import datetime, timedelta, timezone

START = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
ATTACKER_IP = "203.0.113.10"
OTHER_IP = "198.51.100.5"
TARGET_HOST = "web-01"


def _timestamp(minutes: int, seconds: int = 0) -> str:
    return (START + timedelta(minutes=minutes, seconds=seconds)).isoformat()


def _ssh_event(event_id: str, minute: int, outcome: str, *, username: str = "root") -> dict:
    return {
        "event_id": event_id,
        "timestamp": _timestamp(minute),
        "host": TARGET_HOST,
        "event_type": "ssh_login",
        "outcome": outcome,
        "username": username,
        "source_ip": ATTACKER_IP,
        "details": {"method": "ssh"},
    }


def ssh_brute_force_only_scenario() -> list[dict]:
    """Exactly five failed SSH logins within five minutes."""
    return [_ssh_event(f"auth-{index}", index, "failure") for index in range(5)]


def ssh_brute_force_followed_by_success_scenario() -> list[dict]:
    """A brute-force window followed by a same-source, same-host SSH success."""
    return ssh_brute_force_only_scenario() + [_ssh_event("auth-success", 5, "success")]


def ssh_brute_force_success_suspicious_activity_scenario() -> list[dict]:
    """The complete SSH V0.2 attack sequence, excluding unrelated activity."""
    return ssh_brute_force_followed_by_success_scenario() + [
        {
            "event_id": "post-auth-download",
            "timestamp": _timestamp(6),
            "host": TARGET_HOST,
            "event_type": "command_execution",
            "outcome": "success",
            "username": "root",
            "source_ip": ATTACKER_IP,
            "details": {"action": "download_tool"},
        }
    ]


def benign_ssh_activity_scenario() -> list[dict]:
    """Normal SSH activity that remains below the brute-force threshold."""
    return [
        _ssh_event("benign-failure-1", 0, "failure", username="deploy"),
        _ssh_event("benign-failure-2", 2, "failure", username="deploy"),
        _ssh_event("benign-success", 3, "success", username="deploy"),
    ]


def web_reconnaissance_scenario() -> list[dict]:
    """Three distinct sensitive-path probes from one source to one host."""
    paths = ["/.env", "/.git/config", "/wp-admin"]
    return [
        {
            "event_id": f"web-recon-{index}",
            "timestamp": _timestamp(index),
            "host": TARGET_HOST,
            "event_type": "web_request",
            "outcome": "failure",
            "source_ip": ATTACKER_IP,
            "details": {"method": "GET", "path": path, "status_code": 404},
        }
        for index, path in enumerate(paths)
    ]


def benign_web_browsing_scenario() -> list[dict]:
    """Ordinary requests that do not target the sensitive-path allowlist."""
    return [
        {
            "event_id": f"web-benign-{index}",
            "timestamp": _timestamp(index),
            "host": TARGET_HOST,
            "event_type": "web_request",
            "outcome": "success",
            "source_ip": ATTACKER_IP,
            "details": {"method": "GET", "path": path, "status_code": 200},
        }
        for index, path in enumerate(["/", "/products", "/contact"])
    ]


def unrelated_activity_scenario() -> list[dict]:
    """Events that share partial context but must not join the SSH investigation."""
    return [
        {
            "event_id": "other-host-action",
            "timestamp": _timestamp(6),
            "host": "db-01",
            "event_type": "command_execution",
            "outcome": "success",
            "username": "root",
            "source_ip": ATTACKER_IP,
            "details": {"action": "download_tool"},
        },
        {
            "event_id": "other-ip-action",
            "timestamp": _timestamp(6),
            "host": TARGET_HOST,
            "event_type": "command_execution",
            "outcome": "success",
            "username": "root",
            "source_ip": OTHER_IP,
            "details": {"action": "download_tool"},
        },
        {
            "event_id": "other-user-action",
            "timestamp": _timestamp(6),
            "host": TARGET_HOST,
            "event_type": "command_execution",
            "outcome": "success",
            "username": "deploy",
            "source_ip": ATTACKER_IP,
            "details": {"action": "download_tool"},
        },
        {
            "event_id": "outside-window-action",
            "timestamp": _timestamp(21),
            "host": TARGET_HOST,
            "event_type": "command_execution",
            "outcome": "success",
            "username": "root",
            "source_ip": ATTACKER_IP,
            "details": {"action": "download_tool"},
        },
    ]


def ssh_brute_force_investigation_scenario() -> list[dict]:
    """Compatibility name for the full V0.2 SSH investigation scenario."""
    return ssh_brute_force_success_suspicious_activity_scenario() + unrelated_activity_scenario()
