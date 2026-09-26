import pytest
from pydantic import ValidationError

from evaluation.dataset import BENCHMARK_DATASET
from evaluation.models import EvaluationDataset, EvaluationScenario


def test_benchmark_has_unique_ids_and_explicit_ground_truth():
    scenario_ids = [scenario.scenario_id for scenario in BENCHMARK_DATASET.scenarios]

    assert len(scenario_ids) == len(set(scenario_ids))
    assert next(s for s in BENCHMARK_DATASET.scenarios if s.scenario_id == "eval-ssh-brute-force").expected_rule_ids == {"THR-DET-001"}
    assert next(s for s in BENCHMARK_DATASET.scenarios if s.scenario_id == "eval-benign-ssh").expected_rule_ids == set()


def test_expanded_boundary_and_scope_scenarios_have_explicit_ground_truth():
    expected_rule_ids = {
        "eval-ssh-bruteforce-split-scope": set(),
        "eval-ssh-bruteforce-exact-window": {"THR-DET-001"},
        "eval-ssh-success-different-source": {"THR-DET-001"},
        "eval-ssh-success-outside-window": {"THR-DET-001"},
        "eval-web-sensitive-below-threshold": set(),
        "eval-web-sensitive-outside-window": set(),
        "eval-web-sensitive-split-scope": set(),
        "eval-post-auth-wrong-user": {"THR-DET-001", "THR-DET-002"},
        "eval-post-auth-outside-window": {"THR-DET-001", "THR-DET-002"},
    }

    scenarios_by_id = {scenario.scenario_id: scenario for scenario in BENCHMARK_DATASET.scenarios}
    assert {scenario_id: scenarios_by_id[scenario_id].expected_rule_ids for scenario_id in expected_rule_ids} == expected_rule_ids


def test_duplicate_ids_unknown_rules_and_malformed_events_are_rejected():
    scenario = BENCHMARK_DATASET.scenarios[0]
    with pytest.raises(ValidationError, match="unique"):
        EvaluationDataset(scenarios=[scenario, scenario])
    with pytest.raises(ValidationError, match="unknown expected"):
        EvaluationScenario(
            scenario_id="unknown-rule", description="bad label", events=scenario.events,
            expected_rule_ids={"THR-DET-999"},
        )
    with pytest.raises(ValidationError):
        EvaluationScenario(
            scenario_id="bad-event", description="missing host",
            events=[{"event_id": "bad", "timestamp": "2026-01-01T00:00:00+00:00"}],
            expected_rule_ids=set(),
        )
