"""Deterministic orchestration for ShadowTrust detection rules."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol
from uuid import UUID, uuid4

from shadowtrust.detection.context import DetectionContext
from shadowtrust.domain.decisions import (
    DetectionDecision,
    RecommendedAction,
    RiskLevel,
    RuleEvaluation,
    risk_level_for,
)


class DetectionRule(Protocol):
    """Contract implemented by every versioned detection rule."""

    code: str
    version: str

    def evaluate(self, context: DetectionContext) -> RuleEvaluation: ...


def actions_for(level: RiskLevel) -> tuple[RecommendedAction, ...]:
    """Return the simulated response policy for one risk band."""

    policy = {
        RiskLevel.LOW: (RecommendedAction.ALLOW,),
        RiskLevel.GUARDED: (RecommendedAction.MONITOR,),
        RiskLevel.ELEVATED: (RecommendedAction.STEP_UP_AUTH,),
        RiskLevel.HIGH: (
            RecommendedAction.STEP_UP_AUTH,
            RecommendedAction.HOLD_TRANSACTION,
        ),
        RiskLevel.CRITICAL: (
            RecommendedAction.RESTRICT_SESSION,
            RecommendedAction.ANALYST_REVIEW,
        ),
    }
    return policy[level]


@dataclass(frozen=True, slots=True)
class DetectionEngine:
    """Evaluate an ordered rule set and produce one explainable decision."""

    rules: tuple[DetectionRule, ...]
    rule_set_version: str
    engine_version: str
    decision_id_factory: Callable[[], UUID] = field(default=uuid4, repr=False)

    def __post_init__(self) -> None:
        rule_codes = [rule.code for rule in self.rules]
        if len(set(rule_codes)) != len(rule_codes):
            raise ValueError("detection rule codes must be unique")
        if not self.rule_set_version:
            raise ValueError("rule_set_version cannot be empty")
        if not self.engine_version:
            raise ValueError("engine_version cannot be empty")

    def evaluate(self, context: DetectionContext) -> DetectionDecision:
        evaluations = tuple(self._evaluate_rule(rule, context) for rule in self.rules)
        raw_score = context.risk_before + sum(
            result.score_delta for result in evaluations if result.matched
        )
        risk_after = min(100, max(0, raw_score))
        level = risk_level_for(risk_after)

        return DetectionDecision(
            id=self.decision_id_factory(),
            session_id=context.trigger_event.session_id,
            trigger_event_id=context.trigger_event.id,
            risk_before=context.risk_before,
            risk_after=risk_after,
            evaluations=evaluations,
            recommended_actions=actions_for(level),
            explanation=self._build_explanation(evaluations),
            rule_set_version=self.rule_set_version,
            engine_version=self.engine_version,
            baseline_version=context.decision_baseline_version,
        )

    @staticmethod
    def _evaluate_rule(
        rule: DetectionRule, context: DetectionContext
    ) -> RuleEvaluation:
        result = rule.evaluate(context)
        if result.rule_code != rule.code or result.rule_version != rule.version:
            raise ValueError("rule result identity does not match the evaluated rule")
        return result

    @staticmethod
    def _build_explanation(evaluations: tuple[RuleEvaluation, ...]) -> str:
        matched = [
            f"{result.rule_code}: {result.reason}"
            for result in evaluations
            if result.matched
        ]
        if not matched:
            return "No detection rules matched the trigger event."
        return " ".join(matched)
