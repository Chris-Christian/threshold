from evaluation.models import ScenarioEvaluation
from evaluation.runner import calculate_rule_metrics


def result(scenario_id: str, expected: list[str], observed: list[str]) -> ScenarioEvaluation:
    expected_set = set(expected)
    observed_set = set(observed)
    return ScenarioEvaluation(
        scenario_id=scenario_id, expected_rule_ids=expected, observed_rule_ids=observed,
        missing_expected_rule_ids=sorted(expected_set - observed_set),
        unexpected_rule_ids=sorted(observed_set - expected_set),
    )


def test_known_tp_fp_fn_tn_and_metric_calculations():
    metrics = calculate_rule_metrics([
        result("tp", ["THR-DET-001"], ["THR-DET-001"]),
        result("fp", [], ["THR-DET-001"]),
        result("fn", ["THR-DET-001"], []),
        result("tn", [], []),
    ], frozenset({"THR-DET-001"}))[0]

    assert (metrics.true_positives, metrics.false_positives, metrics.false_negatives, metrics.true_negatives) == (1, 1, 1, 1)
    assert metrics.precision == 0.5
    assert metrics.recall == 0.5
    assert metrics.f1 == 0.5


def test_undefined_and_zero_metric_behavior():
    no_observed = calculate_rule_metrics([result("fn", ["THR-DET-001"], [])], frozenset({"THR-DET-001"}))[0]
    no_expected = calculate_rule_metrics([result("tn", [], [])], frozenset({"THR-DET-001"}))[0]
    zero_precision_recall = calculate_rule_metrics([result("fp", [], ["THR-DET-001"]), result("fn", ["THR-DET-001"], [])], frozenset({"THR-DET-001"}))[0]

    assert no_observed.precision is None and no_observed.recall == 0.0 and no_observed.f1 is None
    assert no_expected.precision is None and no_expected.recall is None and no_expected.f1 is None
    assert zero_precision_recall.precision == 0.0
    assert zero_precision_recall.recall == 0.0
    assert zero_precision_recall.f1 is None
