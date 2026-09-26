"""Strict models for labeled deterministic evaluation scenarios and results."""

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.models import SecurityEventInput

TARGET_RULE_IDS = frozenset({"THR-DET-001", "THR-DET-002", "THR-DET-003", "THR-DET-004"})


class EvaluationScenario(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario_id: str = Field(min_length=1)
    description: str = Field(min_length=1)
    events: list[SecurityEventInput] = Field(min_length=1)
    expected_rule_ids: set[str]

    @field_validator("expected_rule_ids")
    @classmethod
    def validate_expected_rule_ids(cls, value: set[str]) -> set[str]:
        unknown_rule_ids = value.difference(TARGET_RULE_IDS)
        if unknown_rule_ids:
            raise ValueError(f"unknown expected rule IDs: {sorted(unknown_rule_ids)}")
        return value


class EvaluationDataset(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenarios: list[EvaluationScenario] = Field(min_length=1)

    @model_validator(mode="after")
    def require_unique_scenario_ids(self) -> "EvaluationDataset":
        scenario_ids = [scenario.scenario_id for scenario in self.scenarios]
        if len(scenario_ids) != len(set(scenario_ids)):
            raise ValueError("evaluation scenario IDs must be unique")
        return self


class ScenarioEvaluation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario_id: str
    expected_rule_ids: list[str]
    observed_rule_ids: list[str]
    missing_expected_rule_ids: list[str]
    unexpected_rule_ids: list[str]


class RuleMetrics(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: str
    true_positives: int = Field(ge=0)
    false_positives: int = Field(ge=0)
    false_negatives: int = Field(ge=0)
    true_negatives: int = Field(ge=0)
    precision: float | None = Field(default=None, ge=0, le=1)
    recall: float | None = Field(default=None, ge=0, le=1)
    f1: float | None = Field(default=None, ge=0, le=1)


class EvaluationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario_results: list[ScenarioEvaluation]
    rule_metrics: list[RuleMetrics]
