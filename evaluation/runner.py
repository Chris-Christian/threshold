"""Run deterministic, labeled rule evaluations without investigations or alerts."""

from app.normalization import normalize_events
from app.workflow import run_detections

from .models import (
    TARGET_RULE_IDS, EvaluationDataset, EvaluationResult, EvaluationScenario,
    RuleMetrics, ScenarioEvaluation,
)


def evaluate_scenario(scenario: EvaluationScenario) -> ScenarioEvaluation:
    """Compare explicit scenario ground truth with observed deterministic rule IDs."""
    normalized_events = normalize_events(scenario.events)
    observed_rule_ids = {match.rule_id for match in run_detections(normalized_events)}
    expected_rule_ids = set(scenario.expected_rule_ids)
    return ScenarioEvaluation(
        scenario_id=scenario.scenario_id,
        expected_rule_ids=sorted(expected_rule_ids),
        observed_rule_ids=sorted(observed_rule_ids),
        missing_expected_rule_ids=sorted(expected_rule_ids.difference(observed_rule_ids)),
        unexpected_rule_ids=sorted(observed_rule_ids.difference(expected_rule_ids)),
    )


def calculate_rule_metrics(
    scenario_results: list[ScenarioEvaluation],
    rule_ids: frozenset[str] = TARGET_RULE_IDS,
) -> list[RuleMetrics]:
    """Calculate one-vs-rest counts and metrics for each target detection rule."""
    metrics = []
    for rule_id in sorted(rule_ids):
        true_positives = false_positives = false_negatives = true_negatives = 0
        for result in scenario_results:
            expected = rule_id in result.expected_rule_ids
            observed = rule_id in result.observed_rule_ids
            if expected and observed:
                true_positives += 1
            elif observed:
                false_positives += 1
            elif expected:
                false_negatives += 1
            else:
                true_negatives += 1

        precision = (
            true_positives / (true_positives + false_positives)
            if true_positives + false_positives else None
        )
        recall = (
            true_positives / (true_positives + false_negatives)
            if true_positives + false_negatives else None
        )
        f1 = (
            2 * precision * recall / (precision + recall)
            if precision is not None and recall is not None and precision + recall > 0
            else None
        )
        metrics.append(RuleMetrics(
            rule_id=rule_id, true_positives=true_positives, false_positives=false_positives,
            false_negatives=false_negatives, true_negatives=true_negatives,
            precision=precision, recall=recall, f1=f1,
        ))
    return metrics


def evaluate_dataset(dataset: EvaluationDataset) -> EvaluationResult:
    """Evaluate all labeled scenarios using only normalization and detection."""
    scenario_results = [evaluate_scenario(scenario) for scenario in dataset.scenarios]
    return EvaluationResult(
        scenario_results=scenario_results,
        rule_metrics=calculate_rule_metrics(scenario_results),
    )
