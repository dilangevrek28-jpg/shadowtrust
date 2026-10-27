"""Corpus replay and measurable detection-quality evaluation."""

from __future__ import annotations

from statistics import mean
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from shadowtrust.detection.context import DetectionContext
from shadowtrust.detection.engine import DetectionEngine
from shadowtrust.domain.decisions import DetectionDecision, RecommendedAction
from shadowtrust.synthetic.scenarios import (
    DatasetSplit,
    ScenarioGroundTruth,
    SyntheticScenario,
)


class ScenarioEvaluation(BaseModel):
    """Timeline decisions and classification result for one scenario."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    scenario_id: UUID
    scenario_name: str
    split: DatasetSplit
    ground_truth: ScenarioGroundTruth
    predicted: ScenarioGroundTruth
    decisions: tuple[DetectionDecision, ...] = Field(min_length=1)
    first_alert_event_id: UUID | None = None
    detection_latency_seconds: float | None = Field(default=None, ge=0)
    unnecessary_step_up_count: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_alert_fields(self) -> ScenarioEvaluation:
        if self.predicted is ScenarioGroundTruth.NORMAL:
            if self.first_alert_event_id is not None:
                raise ValueError("normal prediction cannot have a first alert event")
            if self.detection_latency_seconds is not None:
                raise ValueError("normal prediction cannot have detection latency")
        elif self.first_alert_event_id is None:
            raise ValueError("ATO prediction must reference its first alert event")
        if (
            self.detection_latency_seconds is not None
            and self.ground_truth is not ScenarioGroundTruth.ATO
        ):
            raise ValueError("detection latency is only defined for true ATO scenarios")
        return self


class EvaluationMetrics(BaseModel):
    """Confusion matrix and operational metrics for a scenario corpus."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    true_positives: int = Field(ge=0)
    false_positives: int = Field(ge=0)
    true_negatives: int = Field(ge=0)
    false_negatives: int = Field(ge=0)
    precision: float | None = Field(default=None, ge=0, le=1)
    recall: float | None = Field(default=None, ge=0, le=1)
    false_positive_rate: float | None = Field(default=None, ge=0, le=1)
    average_detection_latency_seconds: float | None = Field(default=None, ge=0)
    unnecessary_step_up_count: int = Field(ge=0)
    total_decisions: int = Field(ge=0)


class EvaluationReport(BaseModel):
    """Complete, immutable result of replaying a corpus."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    alert_threshold: int = Field(ge=0, le=100)
    outcomes: tuple[ScenarioEvaluation, ...] = Field(min_length=1)
    metrics: EvaluationMetrics


def evaluate_scenario(
    scenario: SyntheticScenario,
    engine: DetectionEngine,
    *,
    alert_threshold: int = 70,
) -> ScenarioEvaluation:
    """Replay one event sequence while carrying risk along the trust timeline."""

    if not 0 <= alert_threshold <= 100:
        raise ValueError("alert_threshold must be between 0 and 100")

    risk_before = 0
    prior_events = []
    decisions = []
    first_alert_event_id = None
    first_alert_time = None

    for event in scenario.events:
        context = DetectionContext(
            trigger_event=event,
            prior_events=tuple(prior_events),
            risk_before=risk_before,
            baseline=scenario.baseline,
        )
        decision = engine.evaluate(context)
        decisions.append(decision)
        risk_before = decision.risk_after
        prior_events.append(event)

        if first_alert_event_id is None and decision.risk_after >= alert_threshold:
            first_alert_event_id = event.id
            first_alert_time = event.occurred_at

    predicted = (
        ScenarioGroundTruth.ATO
        if first_alert_event_id is not None
        else ScenarioGroundTruth.NORMAL
    )

    detection_latency_seconds = None
    if scenario.ground_truth is ScenarioGroundTruth.ATO and first_alert_time is not None:
        attack_start_time = next(
            event.occurred_at
            for event in scenario.events
            if event.id == scenario.attack_start_event_id
        )
        detection_latency_seconds = max(
            0.0,
            (first_alert_time - attack_start_time).total_seconds(),
        )

    unnecessary_step_up_count = 0
    if scenario.ground_truth is ScenarioGroundTruth.NORMAL:
        unnecessary_step_up_count = sum(
            RecommendedAction.STEP_UP_AUTH in decision.recommended_actions
            for decision in decisions
        )

    return ScenarioEvaluation(
        scenario_id=scenario.id,
        scenario_name=scenario.name,
        split=scenario.split,
        ground_truth=scenario.ground_truth,
        predicted=predicted,
        decisions=tuple(decisions),
        first_alert_event_id=first_alert_event_id,
        detection_latency_seconds=detection_latency_seconds,
        unnecessary_step_up_count=unnecessary_step_up_count,
    )


def evaluate_corpus(
    scenarios: tuple[SyntheticScenario, ...],
    engine: DetectionEngine,
    *,
    alert_threshold: int = 70,
) -> EvaluationReport:
    """Evaluate a corpus and calculate classification and operational metrics."""

    if not scenarios:
        raise ValueError("evaluation corpus cannot be empty")
    scenario_ids = [scenario.id for scenario in scenarios]
    if len(set(scenario_ids)) != len(scenario_ids):
        raise ValueError("evaluation corpus cannot contain duplicate scenarios")

    outcomes = tuple(
        evaluate_scenario(
            scenario,
            engine,
            alert_threshold=alert_threshold,
        )
        for scenario in scenarios
    )

    true_positives = sum(
        outcome.ground_truth is ScenarioGroundTruth.ATO
        and outcome.predicted is ScenarioGroundTruth.ATO
        for outcome in outcomes
    )
    false_positives = sum(
        outcome.ground_truth is ScenarioGroundTruth.NORMAL
        and outcome.predicted is ScenarioGroundTruth.ATO
        for outcome in outcomes
    )
    true_negatives = sum(
        outcome.ground_truth is ScenarioGroundTruth.NORMAL
        and outcome.predicted is ScenarioGroundTruth.NORMAL
        for outcome in outcomes
    )
    false_negatives = sum(
        outcome.ground_truth is ScenarioGroundTruth.ATO
        and outcome.predicted is ScenarioGroundTruth.NORMAL
        for outcome in outcomes
    )

    latencies = [
        outcome.detection_latency_seconds
        for outcome in outcomes
        if outcome.detection_latency_seconds is not None
    ]
    metrics = EvaluationMetrics(
        true_positives=true_positives,
        false_positives=false_positives,
        true_negatives=true_negatives,
        false_negatives=false_negatives,
        precision=_safe_ratio(true_positives, true_positives + false_positives),
        recall=_safe_ratio(true_positives, true_positives + false_negatives),
        false_positive_rate=_safe_ratio(
            false_positives,
            false_positives + true_negatives,
        ),
        average_detection_latency_seconds=mean(latencies) if latencies else None,
        unnecessary_step_up_count=sum(
            outcome.unnecessary_step_up_count for outcome in outcomes
        ),
        total_decisions=sum(len(outcome.decisions) for outcome in outcomes),
    )
    return EvaluationReport(
        alert_threshold=alert_threshold,
        outcomes=outcomes,
        metrics=metrics,
    )


def _safe_ratio(numerator: int, denominator: int) -> float | None:
    if denominator == 0:
        return None
    return numerator / denominator
