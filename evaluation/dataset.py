"""Fixed, labeled V0.4 benchmark data kept separate from traffic simulation."""

from datetime import datetime, timedelta, timezone

from .models import EvaluationDataset, EvaluationScenario

START = datetime(2026, 2, 1, 9, 0, tzinfo=timezone.utc)
ATTACKER_IP = "203.0.113.77"
OTHER_IP = "198.51.100.77"
HOST = "eval-web-01"


def _time(minute: int) -> str:
    return (START + timedelta(minutes=minute)).isoformat()


def _ssh(event_id: str, minute: int, outcome: str, *, source_ip: str = ATTACKER_IP, host: str = HOST, username: str = "root") -> dict:
    return {
        "event_id": event_id, "timestamp": _time(minute), "host": host,
        "event_type": "ssh_login", "outcome": outcome, "username": username,
        "source_ip": source_ip, "details": {"method": "ssh"},
    }


def _command(event_id: str, minute: int, action: str, *, source_ip: str = ATTACKER_IP, host: str = HOST, username: str = "root") -> dict:
    return {
        "event_id": event_id, "timestamp": _time(minute), "host": host,
        "event_type": "command_execution", "outcome": "success", "username": username,
        "source_ip": source_ip, "details": {"action": action},
    }


def _web(event_id: str, minute: int, path: str, *, source_ip: str = ATTACKER_IP, host: str = HOST, status_code: int = 404) -> dict:
    return {
        "event_id": event_id, "timestamp": _time(minute), "host": host,
        "event_type": "web_request", "outcome": "failure", "source_ip": source_ip,
        "details": {"method": "GET", "path": path, "status_code": status_code},
    }


def _failed_ssh(prefix: str, start: int, count: int = 5) -> list[dict]:
    return [_ssh(f"{prefix}-failure-{index}", start + index, "failure") for index in range(count)]


def build_benchmark_dataset() -> EvaluationDataset:
    """Return explicit ground truth for deterministic V0.4 rule-quality evaluation."""
    return EvaluationDataset(scenarios=[
        EvaluationScenario(
            scenario_id="eval-ssh-brute-force", description="Five SSH failures in five minutes.",
            events=_failed_ssh("bf", 0), expected_rule_ids={"THR-DET-001"},
        ),
        EvaluationScenario(
            scenario_id="eval-ssh-brute-force-success", description="Brute force followed by SSH success.",
            events=_failed_ssh("bf-success", 10) + [_ssh("bf-success-login", 15, "success")],
            expected_rule_ids={"THR-DET-001", "THR-DET-002"},
        ),
        EvaluationScenario(
            scenario_id="eval-ssh-post-auth", description="Brute force, SSH success, and suspicious action.",
            events=_failed_ssh("post-auth", 20) + [_ssh("post-auth-login", 25, "success"), _command("post-auth-action", 26, "disable_logging")],
            expected_rule_ids={"THR-DET-001", "THR-DET-002", "THR-DET-004"},
        ),
        EvaluationScenario(
            scenario_id="eval-benign-ssh", description="Normal SSH use below the brute-force threshold.",
            events=[_ssh("benign-ssh-failure-1", 35, "failure", username="deploy"), _ssh("benign-ssh-failure-2", 38, "failure", username="deploy"), _ssh("benign-ssh-success", 39, "success", username="deploy")],
            expected_rule_ids=set(),
        ),
        EvaluationScenario(
            scenario_id="eval-web-recon", description="Three sensitive web paths probed within five minutes.",
            events=[_web("web-recon-env", 45, "/.env"), _web("web-recon-git", 47, "/.git/config"), _web("web-recon-admin", 50, "/wp-admin")],
            expected_rule_ids={"THR-DET-003"},
        ),
        EvaluationScenario(
            scenario_id="eval-benign-web", description="Ordinary web browsing without sensitive paths.",
            events=[_web("web-home", 55, "/", status_code=200), _web("web-docs", 56, "/docs", status_code=200), _web("web-health", 57, "/health", status_code=200)],
            expected_rule_ids=set(),
        ),
        EvaluationScenario(
            scenario_id="eval-mixed-ssh-unrelated", description="Relevant SSH chain with unrelated source and host activity.",
            events=_failed_ssh("mixed", 65) + [_ssh("mixed-login", 70, "success"), _command("mixed-action", 71, "add_user"), _command("mixed-other-ip", 71, "download_tool", source_ip=OTHER_IP), _command("mixed-other-host", 71, "download_tool", host="eval-db-01")],
            expected_rule_ids={"THR-DET-001", "THR-DET-002", "THR-DET-004"},
        ),
        EvaluationScenario(
            scenario_id="eval-ssh-below-threshold", description="Four failed SSH logins remain below threshold.",
            events=_failed_ssh("below", 80, count=4), expected_rule_ids=set(),
        ),
        EvaluationScenario(
            scenario_id="eval-ssh-exact-threshold", description="Exact SSH failure threshold fires.",
            events=_failed_ssh("exact", 90), expected_rule_ids={"THR-DET-001"},
        ),
        EvaluationScenario(
            scenario_id="eval-ssh-outside-window", description="Five failures outside the five-minute window do not fire.",
            events=[_ssh(f"outside-{index}", 100 + index * 2, "failure") for index in range(5)], expected_rule_ids=set(),
        ),
        EvaluationScenario(
            scenario_id="eval-ssh-bruteforce-split-scope", description="Five SSH failures split across source IP scope.",
            events=_failed_ssh("split-scope", 110, count=4) + [_ssh("split-scope-other-ip", 114, "failure", source_ip=OTHER_IP)],
            expected_rule_ids=set(),
        ),
        EvaluationScenario(
            scenario_id="eval-ssh-bruteforce-exact-window", description="Five SSH failures spanning exactly five minutes.",
            events=[_ssh(f"exact-window-{index}", 120 + index * 1, "failure") for index in range(4)] + [_ssh("exact-window-last", 125, "failure")],
            expected_rule_ids={"THR-DET-001"},
        ),
        EvaluationScenario(
            scenario_id="eval-ssh-success-different-source", description="Brute force followed by an SSH success from another source.",
            events=_failed_ssh("success-other-source", 130) + [_ssh("success-other-source-login", 135, "success", source_ip=OTHER_IP)],
            expected_rule_ids={"THR-DET-001"},
        ),
        EvaluationScenario(
            scenario_id="eval-ssh-success-outside-window", description="Matching SSH success more than 15 minutes after brute force.",
            events=_failed_ssh("success-outside", 140) + [_ssh("success-outside-login", 160, "success")],
            expected_rule_ids={"THR-DET-001"},
        ),
        EvaluationScenario(
            scenario_id="eval-web-sensitive-below-threshold", description="Repeated sensitive requests cover only two distinct paths.",
            events=[_web("web-below-env-1", 170, "/.env"), _web("web-below-env-2", 171, "/.env"), _web("web-below-git", 172, "/.git/config")],
            expected_rule_ids=set(),
        ),
        EvaluationScenario(
            scenario_id="eval-web-sensitive-outside-window", description="Three sensitive paths extend beyond the five-minute window.",
            events=[_web("web-outside-env", 180, "/.env"), _web("web-outside-git", 181, "/.git/config"), _web("web-outside-admin", 186, "/wp-admin")],
            expected_rule_ids=set(),
        ),
        EvaluationScenario(
            scenario_id="eval-web-sensitive-split-scope", description="Sensitive probes are distributed across source IP and host scopes.",
            events=[_web("web-split-env", 190, "/.env"), _web("web-split-git", 191, "/.git/config", source_ip=OTHER_IP), _web("web-split-admin", 192, "/wp-admin", host="eval-db-01")],
            expected_rule_ids=set(),
        ),
        EvaluationScenario(
            scenario_id="eval-post-auth-wrong-user", description="Suspicious action after SSH success belongs to a different user.",
            events=_failed_ssh("wrong-user", 200) + [_ssh("wrong-user-login", 205, "success"), _command("wrong-user-action", 206, "download_tool", username="deploy")],
            expected_rule_ids={"THR-DET-001", "THR-DET-002"},
        ),
        EvaluationScenario(
            scenario_id="eval-post-auth-outside-window", description="Suspicious action occurs more than 15 minutes after SSH success.",
            events=_failed_ssh("post-outside", 220) + [_ssh("post-outside-login", 225, "success"), _command("post-outside-action", 241, "add_user")],
            expected_rule_ids={"THR-DET-001", "THR-DET-002"},
        ),
    ])


BENCHMARK_DATASET = build_benchmark_dataset()
