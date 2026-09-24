from app.workflow import triage
from simulator.linux_auth import ssh_brute_force_investigation_scenario
from simulator.linux_auth import web_reconnaissance_scenario


def test_triage_runs_the_complete_deterministic_ssh_investigation_workflow():
    investigation = triage(ssh_brute_force_investigation_scenario())

    assert [alert.detection.rule_id for alert in investigation.alerts] == [
        "THR-DET-001",
        "THR-DET-002",
        "THR-DET-004",
    ]
    assert [entry.event_id for entry in investigation.timeline] == [
        "auth-0",
        "auth-1",
        "auth-2",
        "auth-3",
        "auth-4",
        "auth-success",
        "post-auth-download",
    ]
    assert set(investigation.correlated_event_ids) == {
        entry.event_id for entry in investigation.timeline
    }


def test_triage_handles_independent_web_reconnaissance_alongside_ssh_rules():
    investigation = triage(ssh_brute_force_investigation_scenario() + web_reconnaissance_scenario())

    assert [alert.detection.rule_id for alert in investigation.alerts] == [
        "THR-DET-001",
        "THR-DET-003",
        "THR-DET-002",
        "THR-DET-004",
    ]
    assert {"web-recon-0", "web-recon-1", "web-recon-2"} <= set(
        investigation.correlated_event_ids
    )
