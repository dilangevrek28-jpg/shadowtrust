from dataclasses import dataclass
from uuid import UUID

import pytest
from pydantic import ValidationError

from shadowtrust.detection.context import DetectionContext
from shadowtrust.detection.engine import DetectionEngine, actions_for
from shadowtrust.domain.decisions import (
    RecommendedAction,
    RiskLevel,
    RuleCategory,
    RuleEvaluation,
)
from shadowtrust.domain.events import parse_security_event


DECISION_ID = UUID("15575448-fcaf-4c9e-912d-36058ee9b425")
LOGIN_EVENT_ID = "c71f1d6a-2d9a-4fd1-a1ad-ec03dfac25ee"
TRANSFER_EVENT_ID = "bb8f378b-95f8-43b6-82a1-bacc09acc0f9"
USER_ID = "232dd896-4bfa-4b90-86cf-11ce7c9bd742"
SESSION_ID = "d844f566-fbd9-432d-9e56-942909319293"
DEVICE_ID = "7bd829e0-0d04-496b-b621-9a08cb00b404"
CORRELATION_ID = "f2d3a104-18ac-4cf6-aec8-2033217910b8"


def login_event() -> object:
    return parse_security_event(
        {
            "id": LOGIN_EVENT_ID,
            "event_type": "login_succeeded",
            "occurred_at": "2026-10-24T08:30:00+03:00",
            "received_at": "2026-10-24T08:30:01+03:00",
            "user_id": USER_ID,
            "session_id": SESSION_ID,
            "device_id": DEVICE_ID,
            "source_ip": "203.0.113.42",
            "geo_country": "TR",
            "correlation_id": CORRELATION_ID,
            "payload": {
                "authentication_method": "password_and_otp",
                "mfa_used": True,
            },
        }
    )


def transfer_event(
    *,
    event_id: str = TRANSFER_EVENT_ID,
    user_id: str = USER_ID,
    session_id: str = SESSION_ID,
) -> object:
    return parse_security_event(
        {
            "id": event_id,
            "event_type": "transfer_initiated",
            "occurred_at": "2026-10-24T08:32:00+03:00",
            "received_at": "2026-10-24T08:32:01+03:00",
            "user_id": user_id,
            "session_id": session_id,
            "device_id": DEVICE_ID,
            "source_ip": "203.0.113.42",
            "geo_country": "TR",
            "correlation_id": CORRELATION_ID,
            "payload": {
                "transaction_id": "d3837b8a-f3d7-4b2c-a224-63d7c260aa07",
                "beneficiary_id": "eb3f2e00-c3a5-4625-bcb6-137f6502ac87",
                "amount": "1250.50",
                "currency": "TRY",
            },
        }
    )


@dataclass(frozen=True)
class FixedRule:
    code: str
    version: str = "2026.1"
    delta: int = 0
    matched: bool = False

    def evaluate(self, context: DetectionContext) -> RuleEvaluation:
        return RuleEvaluation(
            rule_code=self.code,
            rule_version=self.version,
            category=RuleCategory.SIGNAL,
            matched=self.matched,
            score_delta=self.delta if self.matched else 0,
            reason=f"Fixed result for {self.code}.",
            evidence_event_ids=(context.trigger_event.id,) if self.matched else (),
        )


def context_with(risk_before: int = 20) -> DetectionContext:
    return DetectionContext(
        trigger_event=transfer_event(),
        prior_events=(login_event(),),
        risk_before=risk_before,
        baseline_version="baseline-7",
    )


def engine_with(*rules: FixedRule) -> DetectionEngine:
    return DetectionEngine(
        rules=rules,
        rule_set_version="2026.1",
        engine_version="0.1.0",
        decision_id_factory=lambda: DECISION_ID,
    )


def test_engine_evaluates_rules_in_declared_order() -> None:
    engine = engine_with(
        FixedRule(code="NEW_DEVICE", delta=15, matched=True),
        FixedRule(code="KNOWN_COUNTRY"),
        FixedRule(code="NEW_BENEFICIARY_TRANSFER", delta=40, matched=True),
    )

    decision = engine.evaluate(context_with())

    assert decision.id == DECISION_ID
    assert [result.rule_code for result in decision.evaluations] == [
        "NEW_DEVICE",
        "KNOWN_COUNTRY",
        "NEW_BENEFICIARY_TRANSFER",
    ]
    assert decision.risk_before == 20
    assert decision.risk_after == 75
    assert decision.risk_level is RiskLevel.HIGH
    assert decision.recommended_actions == (
        RecommendedAction.STEP_UP_AUTH,
        RecommendedAction.HOLD_TRANSACTION,
    )
    assert decision.baseline_version == "baseline-7"


def test_engine_explanation_contains_only_matched_rules() -> None:
    decision = engine_with(
        FixedRule(code="NEW_DEVICE", delta=15, matched=True),
        FixedRule(code="KNOWN_COUNTRY"),
    ).evaluate(context_with())

    assert "NEW_DEVICE" in decision.explanation
    assert "KNOWN_COUNTRY" not in decision.explanation


def test_engine_explains_when_no_rule_matches() -> None:
    decision = engine_with(FixedRule(code="KNOWN_DEVICE")).evaluate(context_with())

    assert decision.risk_after == 20
    assert decision.explanation == "No detection rules matched the trigger event."


@pytest.mark.parametrize(
    ("level", "expected"),
    [
        (RiskLevel.LOW, (RecommendedAction.ALLOW,)),
        (RiskLevel.GUARDED, (RecommendedAction.MONITOR,)),
        (RiskLevel.ELEVATED, (RecommendedAction.STEP_UP_AUTH,)),
        (
            RiskLevel.HIGH,
            (RecommendedAction.STEP_UP_AUTH, RecommendedAction.HOLD_TRANSACTION),
        ),
        (
            RiskLevel.CRITICAL,
            (RecommendedAction.RESTRICT_SESSION, RecommendedAction.ANALYST_REVIEW),
        ),
    ],
)
def test_action_policy_covers_every_risk_level(
    level: RiskLevel, expected: tuple[RecommendedAction, ...]
) -> None:
    assert actions_for(level) == expected


def test_engine_clamps_score_to_one_hundred() -> None:
    decision = engine_with(
        FixedRule(code="STRONG_SIGNAL", delta=30, matched=True)
    ).evaluate(context_with(risk_before=90))

    assert decision.risk_after == 100
    assert decision.risk_delta == 10
    assert decision.risk_level is RiskLevel.CRITICAL


def test_engine_clamps_recovery_score_to_zero() -> None:
    decision = engine_with(
        FixedRule(code="STRONG_RECOVERY", delta=-30, matched=True)
    ).evaluate(context_with(risk_before=10))

    assert decision.risk_after == 0
    assert decision.risk_delta == -10


def test_context_rejects_duplicate_event_ids() -> None:
    event = transfer_event()

    with pytest.raises(ValidationError, match="duplicate event ids"):
        DetectionContext(
            trigger_event=event,
            prior_events=(event,),
            risk_before=0,
        )


def test_context_rejects_events_from_different_user() -> None:
    other_user = "4c9a2287-66ac-4659-8ca4-6cd80352c949"

    with pytest.raises(ValidationError, match="same user"):
        DetectionContext(
            trigger_event=transfer_event(),
            prior_events=(
                transfer_event(
                    event_id="828e357a-b3c3-4f17-9467-110f91aa1ea6",
                    user_id=other_user,
                ),
            ),
            risk_before=0,
        )


def test_context_rejects_events_from_different_session() -> None:
    other_session = "7604152f-ff17-4575-a238-94782bad5426"

    with pytest.raises(ValidationError, match="share the trigger session"):
        DetectionContext(
            trigger_event=transfer_event(),
            prior_events=(
                transfer_event(
                    event_id="11f4992b-7d9c-4875-a662-eb21796eb181",
                    session_id=other_session,
                ),
            ),
            risk_before=0,
        )


def test_engine_rejects_duplicate_rule_codes() -> None:
    with pytest.raises(ValueError, match="must be unique"):
        engine_with(FixedRule(code="NEW_DEVICE"), FixedRule(code="NEW_DEVICE"))


def test_engine_rejects_rule_result_with_false_identity() -> None:
    @dataclass(frozen=True)
    class MisidentifiedRule:
        code: str = "EXPECTED_CODE"
        version: str = "2026.1"

        def evaluate(self, context: DetectionContext) -> RuleEvaluation:
            return RuleEvaluation(
                rule_code="DIFFERENT_CODE",
                rule_version=self.version,
                category=RuleCategory.SIGNAL,
                matched=False,
                score_delta=0,
                reason="Incorrect rule identity.",
            )

    engine = DetectionEngine(
        rules=(MisidentifiedRule(),),
        rule_set_version="2026.1",
        engine_version="0.1.0",
    )

    with pytest.raises(ValueError, match="identity does not match"):
        engine.evaluate(context_with())
