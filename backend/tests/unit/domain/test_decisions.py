from uuid import UUID

import pytest
from pydantic import ValidationError

from shadowtrust.domain.decisions import (
    DetectionDecision,
    RecommendedAction,
    RiskLevel,
    RuleCategory,
    RuleEvaluation,
    risk_level_for,
)


DECISION_ID = UUID("15575448-fcaf-4c9e-912d-36058ee9b425")
SESSION_ID = UUID("d844f566-fbd9-432d-9e56-942909319293")
LOGIN_EVENT_ID = UUID("c71f1d6a-2d9a-4fd1-a1ad-ec03dfac25ee")
TRANSFER_EVENT_ID = UUID("bb8f378b-95f8-43b6-82a1-bacc09acc0f9")


def matched_rule(
    *,
    code: str = "NEW_DEVICE",
    delta: int = 15,
    evidence: tuple[UUID, ...] = (LOGIN_EVENT_ID,),
) -> RuleEvaluation:
    return RuleEvaluation(
        rule_code=code,
        rule_version="2026.1",
        category=RuleCategory.SIGNAL,
        matched=True,
        score_delta=delta,
        reason="The session uses a device not present in the user baseline.",
        evidence_event_ids=evidence,
    )


def valid_decision() -> DetectionDecision:
    return DetectionDecision(
        id=DECISION_ID,
        session_id=SESSION_ID,
        trigger_event_id=TRANSFER_EVENT_ID,
        risk_before=20,
        risk_after=75,
        evaluations=(
            matched_rule(),
            matched_rule(
                code="NEW_BENEFICIARY_TRANSFER",
                delta=40,
                evidence=(LOGIN_EVENT_ID, TRANSFER_EVENT_ID),
            ),
        ),
        recommended_actions=(RecommendedAction.HOLD_TRANSACTION,),
        explanation="A new device was followed by a transfer to a new beneficiary.",
        rule_set_version="2026.1",
        engine_version="0.1.0",
        baseline_version="baseline-7",
    )


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0, RiskLevel.LOW),
        (24, RiskLevel.LOW),
        (25, RiskLevel.GUARDED),
        (49, RiskLevel.GUARDED),
        (50, RiskLevel.ELEVATED),
        (69, RiskLevel.ELEVATED),
        (70, RiskLevel.HIGH),
        (84, RiskLevel.HIGH),
        (85, RiskLevel.CRITICAL),
        (100, RiskLevel.CRITICAL),
    ],
)
def test_maps_score_boundaries_to_risk_levels(score: int, expected: RiskLevel) -> None:
    assert risk_level_for(score) is expected


def test_builds_explainable_decision_from_rule_deltas() -> None:
    decision = valid_decision()

    assert decision.risk_delta == 55
    assert decision.risk_level is RiskLevel.HIGH
    assert len(decision.evaluations[1].evidence_event_ids) == 2


def test_rejects_score_that_does_not_match_rule_trace() -> None:
    data = valid_decision().model_dump(exclude={"risk_delta", "risk_level"})
    data["risk_after"] = 74

    with pytest.raises(ValidationError, match="risk_after must equal"):
        DetectionDecision.model_validate(data)


def test_clamps_score_at_upper_boundary() -> None:
    decision = DetectionDecision(
        id=DECISION_ID,
        session_id=SESSION_ID,
        trigger_event_id=TRANSFER_EVENT_ID,
        risk_before=90,
        risk_after=100,
        evaluations=(matched_rule(delta=20),),
        recommended_actions=(
            RecommendedAction.RESTRICT_SESSION,
            RecommendedAction.ANALYST_REVIEW,
        ),
        explanation="Risk reached the maximum after a strong signal.",
        rule_set_version="2026.1",
        engine_version="0.1.0",
    )

    assert decision.risk_level is RiskLevel.CRITICAL


def test_clamps_recovery_at_lower_boundary() -> None:
    recovery = RuleEvaluation(
        rule_code="STRONG_MFA_RECOVERY",
        rule_version="2026.1",
        category=RuleCategory.RECOVERY,
        matched=True,
        score_delta=-20,
        reason="A strong MFA challenge was completed on a known device.",
        evidence_event_ids=(LOGIN_EVENT_ID,),
    )
    decision = DetectionDecision(
        id=DECISION_ID,
        session_id=SESSION_ID,
        trigger_event_id=LOGIN_EVENT_ID,
        risk_before=10,
        risk_after=0,
        evaluations=(recovery,),
        recommended_actions=(RecommendedAction.ALLOW,),
        explanation="Strong verification reduced the remaining risk.",
        rule_set_version="2026.1",
        engine_version="0.1.0",
    )

    assert decision.risk_delta == -10
    assert decision.risk_level is RiskLevel.LOW


def test_rejects_matched_rule_without_evidence() -> None:
    with pytest.raises(ValidationError, match="must reference evidence"):
        matched_rule(evidence=())


def test_rejects_unmatched_rule_that_changes_score() -> None:
    with pytest.raises(ValidationError, match="unmatched rule cannot"):
        RuleEvaluation(
            rule_code="NEW_DEVICE",
            rule_version="2026.1",
            category=RuleCategory.SIGNAL,
            matched=False,
            score_delta=15,
            reason="The rule did not match.",
        )


def test_rejects_allow_combined_with_restrictive_action() -> None:
    data = valid_decision().model_dump(exclude={"risk_delta", "risk_level"})
    data["recommended_actions"] = ["allow", "hold_transaction"]

    with pytest.raises(ValidationError, match="allow cannot be combined"):
        DetectionDecision.model_validate(data)


def test_rejects_duplicate_actions() -> None:
    data = valid_decision().model_dump(exclude={"risk_delta", "risk_level"})
    data["recommended_actions"] = ["hold_transaction", "hold_transaction"]

    with pytest.raises(ValidationError, match="must be unique"):
        DetectionDecision.model_validate(data)


def test_decision_is_immutable() -> None:
    decision = valid_decision()

    with pytest.raises(ValidationError, match="Instance is frozen"):
        decision.risk_after = 0  # type: ignore[misc]
