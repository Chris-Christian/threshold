"""Deterministic Linux SSH investigation scenario for local testing.

The sequence models five failed SSH logins, a successful login from the same
source and host, then post-authentication command and file activity. It also
contains unrelated events that correlation must exclude.
"""

from datetime import datetime, timedelta, timezone


def ssh_brute_force_investigation_scenario() -> list[dict]:
    start = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    failed_logins = [
        {
            "event_id": f"auth-{index}",
            "timestamp": (start + timedelta(minutes=index)).isoformat(),
            "host": "web-01",
            "event_type": "ssh_login",
            "outcome": "failure",
            "username": "root",
            "source_ip": "203.0.113.10",
        }
        for index in range(5)
    ]
    return failed_logins + [
        {
            "event_id": "pre-auth-command",
            "timestamp": (start + timedelta(minutes=3, seconds=30)).isoformat(),
            "host": "web-01",
            "event_type": "command_execution",
            "outcome": "success",
            "source_ip": "203.0.113.10",
        },
        {
            "event_id": "auth-success",
            "timestamp": (start + timedelta(minutes=5)).isoformat(),
            "host": "web-01",
            "event_type": "ssh_login",
            "outcome": "success",
            "username": "root",
            "source_ip": "203.0.113.10",
        },
        {
            "event_id": "post-auth-command",
            "timestamp": (start + timedelta(minutes=6)).isoformat(),
            "host": "web-01",
            "event_type": "command_execution",
            "outcome": "success",
            "username": "root",
            "source_ip": "203.0.113.10",
        },
        {
            "event_id": "post-auth-file-access",
            "timestamp": (start + timedelta(minutes=7)).isoformat(),
            "host": "web-01",
            "event_type": "file_access",
            "outcome": "success",
            "username": "root",
            "source_ip": "203.0.113.10",
        },
        {
            "event_id": "other-host",
            "timestamp": (start + timedelta(minutes=6)).isoformat(),
            "host": "db-01",
            "event_type": "command_execution",
            "outcome": "success",
            "source_ip": "203.0.113.10",
        },
        {
            "event_id": "other-source",
            "timestamp": (start + timedelta(minutes=6)).isoformat(),
            "host": "web-01",
            "event_type": "command_execution",
            "outcome": "success",
            "source_ip": "198.51.100.5",
        },
        {
            "event_id": "irrelevant-event-type",
            "timestamp": (start + timedelta(minutes=6)).isoformat(),
            "host": "web-01",
            "event_type": "process_start",
            "outcome": "info",
            "source_ip": "203.0.113.10",
        },
        {
            "event_id": "outside-window",
            "timestamp": (start + timedelta(minutes=25)).isoformat(),
            "host": "web-01",
            "event_type": "command_execution",
            "outcome": "success",
            "source_ip": "203.0.113.10",
        },
    ]
