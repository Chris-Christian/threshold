from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.investigation import begin_investigation, build_investigations, build_timeline, resolve_investigation
from app.models import (
    Alert,
    AlertCorrelation,
    DetectionMatch,
    Investigation,
    InvestigationOutcome,
    InvestigationStatus,
)
from app.normalization import normalize_events
from app.workflow import triage
from simulator.linux_auth import ssh_brute_force_investigation_scenario, web_reconnaissance_scenario


def _event(event_id: str, timestamp: str) -> dict:
    return {
        "event_id": event_id,
        "timestamp": timestamp,
        "host": "web-01",
        "event_type": "ssh_login",
        "outcome": "failure",
        "source_ip": "203.0.113.10",
        "details": {"method": "ssh"},
    }


def _alert(index: int) -> Alert:
    timestamp = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    return Alert(
        alert_id=f"alert-{index}",
        detection=DetectionMatch(
            rule_id=f"TEST-{index}",
            title="test",
            severity="low",
            event_ids=[f"event-{index}"],
            summary="test",
            window_start=timestamp,
            window_end=timestamp,
        ),
    )


def test_creation_retains_alerts_events_evidence_and_open_state():
    investigation = triage(ssh_brute_force_investigation_scenario()).investigations[0]

    assert investigation.investigation_id
    assert investigation.created_at.tzinfo is not None
    assert investigation.status == InvestigationStatus.OPEN
    assert investigation.outcome is None
    assert [alert.detection.rule_id for alert in investigation.alerts] == [
        "THR-DET-001", "THR-DET-002", "THR-DET-004"
    ]
    assert investigation.correlated_event_ids == [item.event_id for item in investigation.evidence]
    assert all(item.event_id in investigation.correlated_event_ids for item in investigation.timeline)
    assert investigation.evidence[-1].details.action == "download_tool"


def test_timeline_uses_timestamp_then_event_id_for_deterministic_ordering():
    events = normalize_events([
        _event("event-b", "2026-01-01T12:00:00+00:00"),
        _event("event-a", "2026-01-01T12:00:00+00:00"),
    ])

    assert [entry.event_id for entry in build_timeline(events)] == ["event-a", "event-b"]


def test_overlapping_and_transitive_alerts_form_one_cluster():
    events = normalize_events([
        _event(f"event-{index}", f"2026-01-01T12:0{index}:00+00:00")
        for index in range(1, 5)
    ])
    correlations = [
        AlertCorrelation(alert=_alert(1), correlated_event_ids=["event-1", "event-2"]),
        AlertCorrelation(alert=_alert(2), correlated_event_ids=["event-2", "event-3"]),
        AlertCorrelation(alert=_alert(3), correlated_event_ids=["event-3", "event-4"]),
    ]

    batch = build_investigations(events, correlations)

    assert len(batch.investigations) == 1
    assert len(batch.investigations[0].alerts) == 3
    assert batch.investigations[0].correlated_event_ids == [
        "event-1", "event-2", "event-3", "event-4"
    ]


def test_unrelated_ssh_and_web_activity_become_separate_investigations():
    batch = triage(ssh_brute_force_investigation_scenario() + web_reconnaissance_scenario())

    assert len(batch.investigations) == 2
    assert sorted(len(investigation.alerts) for investigation in batch.investigations) == [1, 3]
    assert all(
        not ({"auth-0", "web-recon-0"} <= set(investigation.correlated_event_ids))
        for investigation in batch.investigations
    )


def test_alert_ids_are_deterministic_for_same_normalized_detection():
    first = triage(ssh_brute_force_investigation_scenario()).alerts
    second = triage(ssh_brute_force_investigation_scenario()).alerts

    assert [alert.alert_id for alert in first] == [alert.alert_id for alert in second]


def test_alert_identity_changes_when_a_semantic_detection_field_changes():
    first = triage(ssh_brute_force_investigation_scenario()).alerts[0]
    changed_events = ssh_brute_force_investigation_scenario()
    for event in changed_events:
        if event["source_ip"] == "203.0.113.10":
            event["source_ip"] = "198.51.100.5"
    second = triage(changed_events).alerts[0]

    assert first.alert_id != second.alert_id


def test_lifecycle_transitions_and_all_outcomes():
    for outcome in InvestigationOutcome:
        investigation = triage(ssh_brute_force_investigation_scenario()).investigations[0]
        investigating = begin_investigation(investigation)
        resolved = resolve_investigation(investigating, outcome)

        assert investigating.status == InvestigationStatus.INVESTIGATING
        assert resolved.status == InvestigationStatus.RESOLVED
        assert resolved.outcome == outcome


def test_invalid_transitions_and_outcome_invariants_are_rejected():
    investigation = triage(ssh_brute_force_investigation_scenario()).investigations[0]

    with pytest.raises(ValueError, match="only INVESTIGATING"):
        resolve_investigation(investigation, InvestigationOutcome.TRUE_POSITIVE)

    investigating = begin_investigation(investigation)
    with pytest.raises(ValueError, match="requires an outcome"):
        resolve_investigation(investigating, None)

    resolved = resolve_investigation(investigating, InvestigationOutcome.BENIGN)
    with pytest.raises(ValueError, match="only OPEN"):
        begin_investigation(resolved)
    with pytest.raises(ValueError, match="only INVESTIGATING"):
        resolve_investigation(resolved, InvestigationOutcome.FALSE_POSITIVE)

    values = investigation.model_dump()
    values["outcome"] = InvestigationOutcome.BENIGN
    with pytest.raises(ValidationError, match="outcome is allowed only"):
        Investigation.model_validate(values)

    values = resolved.model_dump()
    values["outcome"] = None
    with pytest.raises(ValidationError, match="require an outcome"):
        Investigation.model_validate(values)

    with pytest.raises(ValidationError, match="require an outcome"):
        resolved.outcome = None
    with pytest.raises(ValidationError, match="outcome is allowed only"):
        investigation.outcome = InvestigationOutcome.BENIGN
    with pytest.raises(ValidationError, match="require an outcome"):
        investigation.status = InvestigationStatus.RESOLVED


def test_end_to_end_investigation_can_be_resolved_after_clustering():
    batch = triage(ssh_brute_force_investigation_scenario() + web_reconnaissance_scenario())
    ssh_investigation = next(
        investigation
        for investigation in batch.investigations
        if any(alert.detection.rule_id == "THR-DET-004" for alert in investigation.alerts)
    )

    resolved = resolve_investigation(
        begin_investigation(ssh_investigation), InvestigationOutcome.TRUE_POSITIVE
    )

    assert resolved.status == InvestigationStatus.RESOLVED
    assert resolved.outcome == InvestigationOutcome.TRUE_POSITIVE
    assert [entry.event_id for entry in resolved.timeline] == [
        "auth-0", "auth-1", "auth-2", "auth-3", "auth-4", "auth-success", "post-auth-download"
    ]


def test_build_investigations_rejects_empty_or_unknown_correlations():
    events = normalize_events([_event("event-1", "2026-01-01T12:00:00+00:00")])

    with pytest.raises(ValueError, match="at least one"):
        build_investigations(events, [AlertCorrelation(alert=_alert(1), correlated_event_ids=[])])
    with pytest.raises(ValueError, match="unknown event IDs"):
        build_investigations(events, [AlertCorrelation(alert=_alert(1), correlated_event_ids=["missing"])])


def test_store_returns_copies_and_preserves_terminal_state():
    from app.investigation import InMemoryInvestigationStore

    store = InMemoryInvestigationStore()
    created = store.add_batch(triage(ssh_brute_force_investigation_scenario()))
    investigation_id = created.investigations[0].investigation_id
    created.investigations[0].status = InvestigationStatus.INVESTIGATING
    assert store.get(investigation_id).status == InvestigationStatus.OPEN
    retrieved = store.get(investigation_id)
    assert retrieved is not None
    retrieved.status = InvestigationStatus.INVESTIGATING

    stored = store.get(investigation_id)
    assert stored is not None
    assert stored.status == InvestigationStatus.OPEN

    store.begin(investigation_id)
    resolved = store.resolve(investigation_id, InvestigationOutcome.BENIGN)
    resolved.outcome = InvestigationOutcome.FALSE_POSITIVE

    final = store.get(investigation_id)
    assert final is not None
    assert final.status == InvestigationStatus.RESOLVED
    assert final.outcome == InvestigationOutcome.BENIGN
