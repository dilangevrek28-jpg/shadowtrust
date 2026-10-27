"""Explainable, deterministic detection-decision models."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, computed_field, model_validator


RiskScore = Annotated[int, Field(ge=0, le=100)]


class RiskLevel(StrEnum):
    LOW = "low"
    GUARDED = "guarded"
    ELEVATED = "elevated"
    HIGH = "high"
    CRITICAL = "critical"


class RuleCategory(StrEnum):
    SIGNAL = "signal"
    CONTRADICTION = "contradiction"
    RECOVERY = "recovery"


class RecommendedAction(StrEnum):
    ALLOW = "allow"
    MONITOR = "monitor"
    STEP_UP_AUTH = "step_up_auth"
    HOLD_TRANSACTION = "hold_transaction"
    RESTRICT_SESSION = "restrict_session"
    ANALYST_REVIEW = "analyst_review"


def risk_level_for(score: int) -> RiskLevel:
    """Map a validated 0-100 score to its stable risk band."""

    if not 0 <= score <= 100:
        raise ValueError("risk score must be between 0 and 100")
    if score <= 24:
        return RiskLevel.LOW
    if score <= 49:
        return RiskLevel.GUARDED
    if score <= 69:
        return RiskLevel.ELEVATED
    if score <= 84:
        return RiskLevel.HIGH
    return RiskLevel.CRITICAL


class RuleEvaluation(BaseModel):
    """Auditable result of evaluating one versioned detection rule."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    rule_code: str = Field(pattern=r"^[A-Z][A-Z0-9_]{2,63}$")
    rule_version: str = Field(min_length=1, max_length=32)
    category: RuleCategory
    matched: bool
    score_delta: int = Field(ge=-100, le=100)
    reason: str = Field(min_length=1, max_length=500)
    evidence_event_ids: tuple[UUID, ...] = ()

    @model_validator(mode="after")
    def validate_match_evidence(self) -> RuleEvaluation:
        if self.matched:
            if self.score_delta == 0:
                raise ValueError("matched rule must change the risk score")
            if not self.evidence_event_ids:
                raise ValueError("matched rule must reference evidence events")
        elif self.score_delta != 0 or self.evidence_event_ids:
            raise ValueError("unmatched rule cannot change score or claim evidence")
        return self


class DetectionDecision(BaseModel):
    """Immutable and replayable result produced for one trigger event."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: UUID
    session_id: UUID
    trigger_event_id: UUID
    risk_before: RiskScore
    risk_after: RiskScore
    evaluations: tuple[RuleEvaluation, ...]
    recommended_actions: tuple[RecommendedAction, ...] = Field(min_length=1)
    explanation: str = Field(min_length=1, max_length=1000)
    rule_set_version: str = Field(min_length=1, max_length=32)
    engine_version: str = Field(min_length=1, max_length=32)
    baseline_version: str | None = Field(default=None, max_length=32)

    @computed_field
    @property
    def risk_delta(self) -> int:
        return self.risk_after - self.risk_before

    @computed_field
    @property
    def risk_level(self) -> RiskLevel:
        return risk_level_for(self.risk_after)

    @model_validator(mode="after")
    def validate_score_trace(self) -> DetectionDecision:
        raw_score = self.risk_before + sum(
            evaluation.score_delta
            for evaluation in self.evaluations
            if evaluation.matched
        )
        expected_score = min(100, max(0, raw_score))
        if self.risk_after != expected_score:
            raise ValueError(
                "risk_after must equal risk_before plus matched rule deltas, "
                "clamped to 0..100"
            )
        return self

    @model_validator(mode="after")
    def validate_actions(self) -> DetectionDecision:
        if len(set(self.recommended_actions)) != len(self.recommended_actions):
            raise ValueError("recommended actions must be unique")
        if (
            RecommendedAction.ALLOW in self.recommended_actions
            and len(self.recommended_actions) > 1
        ):
            raise ValueError("allow cannot be combined with restrictive actions")
        return self
