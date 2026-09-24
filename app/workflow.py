"""Orchestrate normalized events through independently registered rules."""

from collections.abc import Callable
from dataclasses import dataclass
from uuid import uuid4

from detections.ssh_bruteforce import detect_ssh_brute_force
from detections.ssh_success_after_bruteforce import detect_ssh_success_after_bruteforce
from detections.suspicious_post_auth import detect_suspicious_post_auth_activity
from detections.web_reconnaissance import detect_web_reconnaissance

from .correlation import correlate_events
from .investigation import build_timeline
from .models import Alert, Investigation
from .normalization import normalize_events


RuleRunner = Callable[[list, dict[str, list]], list]


@dataclass(frozen=True)
class RuleDefinition:
    rule_id: str
    dependencies: tuple[str, ...]
    run: RuleRunner


RULES = (
    RuleDefinition("THR-DET-001", (), lambda events, _: detect_ssh_brute_force(events)),
    RuleDefinition("THR-DET-003", (), lambda events, _: detect_web_reconnaissance(events)),
    RuleDefinition(
        "THR-DET-002",
        ("THR-DET-001",),
        lambda events, matches: detect_ssh_success_after_bruteforce(events, matches["THR-DET-001"]),
    ),
    RuleDefinition(
        "THR-DET-004",
        ("THR-DET-002",),
        lambda events, matches: detect_suspicious_post_auth_activity(events, matches["THR-DET-002"]),
    ),
)


def run_detections(events: list) -> list:
    """Run rules when their declared match dependencies are available.

    Normalized events remain the source of truth; dependent rule functions
    re-check event fields and windows before creating their own matches.
    """
    matches_by_rule: dict[str, list] = {}
    pending = list(RULES)
    while pending:
        ready = [rule for rule in pending if all(dep in matches_by_rule for dep in rule.dependencies)]
        if not ready:
            raise RuntimeError("detection rule dependencies are cyclic or unavailable")
        for rule in ready:
            matches_by_rule[rule.rule_id] = rule.run(events, matches_by_rule)
            pending.remove(rule)
    return [match for rule in RULES for match in matches_by_rule[rule.rule_id]]


def triage(raw_events: list[dict]) -> Investigation:
    events = normalize_events(raw_events)
    matches = run_detections(events)
    alerts = [Alert(alert_id=str(uuid4()), detection=match) for match in matches]

    correlated = {
        event.event_id
        for match in matches
        for event in correlate_events(events, match)
    }
    related_events = [event for event in events if event.event_id in correlated]
    return Investigation(
        alerts=alerts,
        correlated_event_ids=sorted(correlated),
        timeline=build_timeline(related_events),
    )
