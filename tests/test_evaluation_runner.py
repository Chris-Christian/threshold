from evaluation.dataset import BENCHMARK_DATASET
from evaluation.models import EvaluationDataset, EvaluationScenario
from evaluation.runner import evaluate_dataset, evaluate_scenario


def scenario(scenario_id: str, events: list[dict], expected_rule_ids: set[str]) -> EvaluationScenario:
    return EvaluationScenario(
        scenario_id=scenario_id, description="test scenario", events=events,
        expected_rule_ids=expected_rule_ids,
    )


def test_runner_reports_expected_missing_unexpected_and_no_detection():
    brute_force = next(item for item in BENCHMARK_DATASET.scenarios if item.scenario_id == "eval-ssh-brute-force")
    below_threshold = next(item for item in BENCHMARK_DATASET.scenarios if item.scenario_id == "eval-ssh-below-threshold")
    expected_missing = scenario("expected-missing", below_threshold.events, {"THR-DET-001"})
    unexpected = scenario("unexpected", brute_force.events, set())

    present = evaluate_scenario(brute_force)
    missing = evaluate_scenario(expected_missing)
    extra = evaluate_scenario(unexpected)
    none = evaluate_scenario(below_threshold)

    assert present.missing_expected_rule_ids == []
    assert missing.missing_expected_rule_ids == ["THR-DET-001"]
    assert extra.unexpected_rule_ids == ["THR-DET-001"]
    assert none.observed_rule_ids == []


def test_runner_handles_multi_rule_ssh_and_independent_web_scenarios():
    ssh = next(item for item in BENCHMARK_DATASET.scenarios if item.scenario_id == "eval-ssh-post-auth")
    web = next(item for item in BENCHMARK_DATASET.scenarios if item.scenario_id == "eval-web-recon")

    assert evaluate_scenario(ssh).observed_rule_ids == ["THR-DET-001", "THR-DET-002", "THR-DET-004"]
    assert evaluate_scenario(web).observed_rule_ids == ["THR-DET-003"]


def test_complete_fixed_dataset_runs_end_to_end_with_stable_results():
    first = evaluate_dataset(BENCHMARK_DATASET)
    second = evaluate_dataset(BENCHMARK_DATASET)

    assert first == second
    assert len(first.scenario_results) == len(BENCHMARK_DATASET.scenarios)
    assert [metric.rule_id for metric in first.rule_metrics] == [
        "THR-DET-001", "THR-DET-002", "THR-DET-003", "THR-DET-004"
    ]
