from app.workflow import triage
from simulator.linux_auth import ssh_brute_force_investigation_scenario


def test_triage_runs_the_complete_deterministic_ssh_investigation_workflow():
    investigation = triage(ssh_brute_force_investigation_scenario())

    assert len(investigation.alerts) == 1
    assert investigation.alerts[0].detection.rule_id == "SSH_BRUTE_FORCE"
    assert [entry.event_id for entry in investigation.timeline] == [
        "auth-0",
        "auth-1",
        "auth-2",
        "auth-3",
        "auth-4",
        "auth-success",
        "post-auth-command",
        "post-auth-file-access",
    ]
    assert set(investigation.correlated_event_ids) == {
        entry.event_id for entry in investigation.timeline
    }
