"""Orchestrate normalized events through independently registered rules."""

from collections.abc import Callable
from dataclasses import dataclass
from uuid import NAMESPACE_URL, uuid5

from detections.ssh_bruteforce import detect_ssh_brute_force
from detections.ssh_success_after_bruteforce import detect_ssh_success_after_bruteforce
from detections.suspicious_post_auth import detect_suspicious_post_auth_activity
from detections.web_reconnaissance import detect_web_reconnaissance

from .correlation import correlate_events
from .investigation import build_investigations
from .models import Alert, AlertCorrelation, DetectionMatch, InvestigationBatch, SecurityEvent
from .normalization import normalize_events


RuleRunner = Callable[[list[SecurityEvent], dict[str, list[DetectionMatch]]], list[DetectionMatch]]


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


def run_detections(events: list[SecurityEvent]) -> list[DetectionMatch]:
    """Run rules when their declared match dependencies are available.

    Normalized events remain the source of truth; dependent rule functions
    re-check event fields and windows before creating their own matches.
    """
    matches_by_rule: dict[str, list[DetectionMatch]] = {}
    pending = list(RULES)
    while pending:
        ready = [rule for rule in pending if all(dep in matches_by_rule for dep in rule.dependencies)]
        if not ready:
            raise RuntimeError("detection rule dependencies are cyclic or unavailable")
        for rule in ready:
            matches_by_rule[rule.rule_id] = rule.run(events, matches_by_rule)
            pending.remove(rule)
    return [match for rule in RULES for match in matches_by_rule[rule.rule_id]]


def _alert_identity(match: DetectionMatch) -> str:
    """Stable identity from rule, bounded scope, and normalized triggering events."""
    return "|".join([
        match.rule_id, match.host or "", match.source_ip or "", match.username or "",
        match.window_start.isoformat(), match.window_end.isoformat(), *sorted(match.event_ids),
    ])


def create_alert(match: DetectionMatch) -> Alert:
    return Alert(alert_id=str(uuid5(NAMESPACE_URL, _alert_identity(match))), detection=match)


def triage(raw_events: list[dict]) -> InvestigationBatch:
    events = normalize_events(raw_events)
    matches = run_detections(events)
    alerts = [create_alert(match) for match in matches]
    correlations = [
        AlertCorrelation(
            alert=alert,
            correlated_event_ids=[event.event_id for event in correlate_events(events, alert.detection)],
        )
        for alert in alerts
    ]
    return build_investigations(events, correlations)
