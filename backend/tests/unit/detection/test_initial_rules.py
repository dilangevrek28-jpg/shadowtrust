from uuid import UUID

import pytest

from shadowtrust.detection.context import DetectionContext
from shadowtrust.detection.engine import DetectionEngine
from shadowtrust.detection.rules.initial import (
    AccountRecoveryDeviceRegistrationRule,
    NewDeviceRule,
    PasswordBeneficiaryTransferRule,
    RecoveryDeviceThenTransferRule,
    RepeatedMfaFailuresThenApprovalRule,
    RepeatedInvalidCredentialsThenSuccessRule,
    SessionContextSwitchBeforeTransferRule,
    UnusualCountryRule,
)
from shadowtrust.domain.baselines import UserBaseline
from shadowtrust.domain.decisions import RecommendedAction, RiskLevel, RuleCategory
from shadowtrust.domain.events import parse_security_event


USER_ID = "232dd896-4bfa-4b90-86cf-11ce7c9bd742"
SESSION_ID = "d844f566-fbd9-432d-9e56-942909319293"
KNOWN_DEVICE_ID = "7bd829e0-0d04-496b-b621-9a08cb00b404"
NEW_DEVICE_ID = "47461c2e-e8e9-43c2-b78c-a13d31cce152"
CORRELATION_ID = "f2d3a104-18ac-4cf6-aec8-2033217910b8"
REGISTRATION_EVENT_ID = "9b9bb0df-133f-436a-8ddc-269bc27bfbdf"
TRANSFER_EVENT_ID = "bb8f378b-95f8-43b6-82a1-bacc09acc0f9"
DECISION_ID = UUID("15575448-fcaf-4c9e-912d-36058ee9b425")


def baseline(
    *,
    devices: set[str] | None = None,
    countries: set[str] | None = None,
) -> UserBaseline:
    return UserBaseline(
        user_id=USER_ID,
        version="baseline-7",
        generated_at="2026-10-24T08:00:00+03:00",
        sample_size=42,
        known_device_ids=devices or set(),
        known_countries=countries or set(),
    )


def transfer_event(
    *,
    occurred_at: str = "2026-10-24T08:20:00+03:00",
    device_id: str = NEW_DEVICE_ID,
    country: str = "US",
):
    return parse_security_event(
        {
            "id": TRANSFER_EVENT_ID,
            "event_type": "transfer_initiated",
            "occurred_at": occurred_at,
            "received_at": occurred_at,
            "user_id": USER_ID,
            "session_id": SESSION_ID,
            "device_id": device_id,
            "source_ip": "203.0.113.42",
            "geo_country": country,
            "correlation_id": CORRELATION_ID,
            "payload": {
                "transaction_id": "d3837b8a-f3d7-4b2c-a224-63d7c260aa07",
                "beneficiary_id": "eb3f2e00-c3a5-4625-bcb6-137f6502ac87",
                "amount": "1250.50",
                "currency": "TRY",
            },
        }
    )


def device_registration_event(
    *,
    occurred_at: str = "2026-10-24T08:00:00+03:00",
    method: str = "recovery_flow",
):
    return parse_security_event(
        {
            "id": REGISTRATION_EVENT_ID,
            "event_type": "device_registered",
            "occurred_at": occurred_at,
            "received_at": occurred_at,
            "user_id": USER_ID,
            "session_id": SESSION_ID,
            "device_id": NEW_DEVICE_ID,
            "source_ip": "203.0.113.42",
            "geo_country": "US",
            "correlation_id": CORRELATION_ID,
            "payload": {"registration_method": method},
        }
    )


def context_for(trigger, *, prior=(), user_baseline=None, risk_before=0):
    return DetectionContext(
        trigger_event=trigger,
        prior_events=prior,
        risk_before=risk_before,
        baseline=user_baseline,
    )


def test_new_device_rule_matches_device_absent_from_baseline() -> None:
    result = NewDeviceRule().evaluate(
        context_for(
            transfer_event(),
            user_baseline=baseline(devices={KNOWN_DEVICE_ID}),
        )
    )

    assert result.matched is True
    assert result.score_delta == 15
    assert result.evidence_event_ids == (UUID(TRANSFER_EVENT_ID),)


def test_new_device_rule_does_not_treat_empty_history_as_suspicious() -> None:
    result = NewDeviceRule().evaluate(
        context_for(transfer_event(), user_baseline=baseline())
    )

    assert result.matched is False
    assert result.score_delta == 0


@pytest.mark.parametrize("country", ["TR", "DE"])
def test_unusual_country_rule_accepts_known_countries(country: str) -> None:
    result = UnusualCountryRule().evaluate(
        context_for(
            transfer_event(country=country),
            user_baseline=baseline(countries={"TR", "DE"}),
        )
    )

    assert result.matched is False


def test_unusual_country_rule_matches_country_absent_from_baseline() -> None:
    result = UnusualCountryRule().evaluate(
        context_for(
            transfer_event(country="US"),
            user_baseline=baseline(countries={"TR", "DE"}),
        )
    )

    assert result.matched is True
    assert result.score_delta == 20


def test_recovery_registration_rule_matches_recovery_flow() -> None:
    result = AccountRecoveryDeviceRegistrationRule().evaluate(
        context_for(device_registration_event())
    )

    assert result.matched is True
    assert result.score_delta == 25
    assert result.category is RuleCategory.SIGNAL


def test_recovery_registration_rule_ignores_mfa_verified_registration() -> None:
    result = AccountRecoveryDeviceRegistrationRule().evaluate(
        context_for(device_registration_event(method="mfa_verified"))
    )

    assert result.matched is False


def test_contradiction_matches_transfer_within_thirty_minutes() -> None:
    result = RecoveryDeviceThenTransferRule().evaluate(
        context_for(
            transfer_event(occurred_at="2026-10-24T08:20:00+03:00"),
            prior=(
                device_registration_event(
                    occurred_at="2026-10-24T08:00:00+03:00"
                ),
            ),
        )
    )

    assert result.matched is True
    assert result.score_delta == 40
    assert result.category is RuleCategory.CONTRADICTION
    assert result.evidence_event_ids == (
        UUID(REGISTRATION_EVENT_ID),
        UUID(TRANSFER_EVENT_ID),
    )


def test_contradiction_does_not_match_outside_time_window() -> None:
    result = RecoveryDeviceThenTransferRule().evaluate(
        context_for(
            transfer_event(occurred_at="2026-10-24T08:31:00+03:00"),
            prior=(device_registration_event(),),
        )
    )

    assert result.matched is False


def test_new_device_and_country_are_not_scored_twice_in_one_session() -> None:
    prior = device_registration_event()
    user_baseline = baseline(devices={KNOWN_DEVICE_ID}, countries={"TR"})
    context = context_for(
        transfer_event(),
        prior=(prior,),
        user_baseline=user_baseline,
        risk_before=35,
    )

    device_result = NewDeviceRule().evaluate(context)
    country_result = UnusualCountryRule().evaluate(context)

    assert device_result.matched is False
    assert country_result.matched is False


def test_initial_rule_set_builds_a_cumulative_trust_timeline() -> None:
    engine = DetectionEngine(
        rules=(
            NewDeviceRule(),
            UnusualCountryRule(),
            AccountRecoveryDeviceRegistrationRule(),
            RecoveryDeviceThenTransferRule(),
        ),
        rule_set_version="2026.1",
        engine_version="0.1.0",
        decision_id_factory=lambda: DECISION_ID,
    )
    user_baseline = baseline(
        devices={KNOWN_DEVICE_ID},
        countries={"TR"},
    )
    registration = device_registration_event()
    registration_decision = engine.evaluate(
        context_for(
            registration,
            user_baseline=user_baseline,
        )
    )
    transfer_decision = engine.evaluate(
        context_for(
            transfer_event(),
            prior=(registration,),
            user_baseline=user_baseline,
            risk_before=registration_decision.risk_after,
        )
    )

    assert registration_decision.risk_after == 60
    assert "NEW_DEVICE" in registration_decision.explanation
    assert "UNUSUAL_COUNTRY" in registration_decision.explanation
    assert "ACCOUNT_RECOVERY_DEVICE_REGISTRATION" in (
        registration_decision.explanation
    )
    assert transfer_decision.risk_before == 60
    assert transfer_decision.risk_after == 100
    assert transfer_decision.risk_delta == 40
    assert transfer_decision.risk_level is RiskLevel.CRITICAL
    assert transfer_decision.recommended_actions == (
        RecommendedAction.RESTRICT_SESSION,
        RecommendedAction.ANALYST_REVIEW,
    )
    assert transfer_decision.baseline_version == "baseline-7"
    assert "RECOVERY_DEVICE_THEN_TRANSFER" in transfer_decision.explanation
    assert "NEW_DEVICE" not in transfer_decision.explanation
    assert "UNUSUAL_COUNTRY" not in transfer_decision.explanation


def password_change_event(*, occurred_at: str = "2026-10-24T08:00:00+03:00"):
    return parse_security_event(
        {
            "id": "8cc1c709-3d79-4ab2-8f2e-73d26dc74f8e",
            "event_type": "password_changed",
            "occurred_at": occurred_at,
            "received_at": occurred_at,
            "user_id": USER_ID,
            "session_id": SESSION_ID,
            "device_id": KNOWN_DEVICE_ID,
            "source_ip": "203.0.113.42",
            "geo_country": "TR",
            "correlation_id": CORRELATION_ID,
            "payload": {"method": "authenticated_session"},
        }
    )


def beneficiary_event(
    *,
    occurred_at: str = "2026-10-24T08:05:00+03:00",
    beneficiary_id: str = "eb3f2e00-c3a5-4625-bcb6-137f6502ac87",
):
    return parse_security_event(
        {
            "id": "d3e69a4e-4d2d-4d46-97f4-dc06d0878466",
            "event_type": "beneficiary_added",
            "occurred_at": occurred_at,
            "received_at": occurred_at,
            "user_id": USER_ID,
            "session_id": SESSION_ID,
            "device_id": KNOWN_DEVICE_ID,
            "source_ip": "203.0.113.42",
            "geo_country": "TR",
            "correlation_id": CORRELATION_ID,
            "payload": {
                "beneficiary_id": beneficiary_id,
                "bank_country": "TR",
            },
        }
    )


def test_password_beneficiary_transfer_sequence_matches() -> None:
    password = password_change_event()
    beneficiary = beneficiary_event()
    trigger = transfer_event(occurred_at="2026-10-24T08:10:00+03:00")

    result = PasswordBeneficiaryTransferRule().evaluate(
        context_for(trigger, prior=(password, beneficiary))
    )

    assert result.matched is True
    assert result.score_delta == 70
    assert result.category is RuleCategory.CONTRADICTION
    assert result.evidence_event_ids == (password.id, beneficiary.id, trigger.id)


def test_password_beneficiary_transfer_requires_correct_order() -> None:
    password = password_change_event(occurred_at="2026-10-24T08:06:00+03:00")
    beneficiary = beneficiary_event(occurred_at="2026-10-24T08:05:00+03:00")

    result = PasswordBeneficiaryTransferRule().evaluate(
        context_for(
            transfer_event(occurred_at="2026-10-24T08:10:00+03:00"),
            prior=(beneficiary, password),
        )
    )

    assert result.matched is False


def test_password_beneficiary_transfer_requires_same_beneficiary() -> None:
    other_beneficiary = "24ae460a-35b1-4c37-aa7a-c945f46d145c"
    result = PasswordBeneficiaryTransferRule().evaluate(
        context_for(
            transfer_event(occurred_at="2026-10-24T08:10:00+03:00"),
            prior=(
                password_change_event(),
                beneficiary_event(beneficiary_id=other_beneficiary),
            ),
        )
    )

    assert result.matched is False


def test_password_beneficiary_transfer_respects_fifteen_minute_window() -> None:
    result = PasswordBeneficiaryTransferRule().evaluate(
        context_for(
            transfer_event(occurred_at="2026-10-24T08:16:00+03:00"),
            prior=(password_change_event(), beneficiary_event()),
        )
    )

    assert result.matched is False


def test_password_beneficiary_transfer_requires_transfer_trigger() -> None:
    result = PasswordBeneficiaryTransferRule().evaluate(
        context_for(password_change_event())
    )

    assert result.matched is False


def mfa_failure_event(index: int, minute: int, *, reason: str = "mfa_failed"):
    occurred_at = f"2026-10-24T08:{minute:02d}:00+03:00"
    return parse_security_event(
        {
            "id": f"10000000-0000-4000-8000-{index:012d}",
            "event_type": "login_failed",
            "occurred_at": occurred_at,
            "received_at": occurred_at,
            "user_id": USER_ID,
            "session_id": SESSION_ID,
            "device_id": NEW_DEVICE_ID,
            "source_ip": "203.0.113.42",
            "geo_country": "US",
            "correlation_id": CORRELATION_ID,
            "payload": {"reason": reason},
        }
    )


def mfa_completed_event(*, minute: int = 3, outcome: str = "approved"):
    occurred_at = f"2026-10-24T08:{minute:02d}:00+03:00"
    return parse_security_event(
        {
            "id": "20000000-0000-4000-8000-000000000001",
            "event_type": "mfa_challenge_completed",
            "occurred_at": occurred_at,
            "received_at": occurred_at,
            "user_id": USER_ID,
            "session_id": SESSION_ID,
            "device_id": NEW_DEVICE_ID,
            "source_ip": "203.0.113.42",
            "geo_country": "US",
            "correlation_id": CORRELATION_ID,
            "payload": {"outcome": outcome},
        }
    )


def test_repeated_mfa_failures_then_approval_matches() -> None:
    failures = tuple(mfa_failure_event(index, index) for index in range(3))
    approval = mfa_completed_event()

    result = RepeatedMfaFailuresThenApprovalRule().evaluate(
        context_for(approval, prior=failures)
    )

    assert result.matched is True
    assert result.score_delta == 35
    assert result.category is RuleCategory.CONTRADICTION
    assert result.evidence_event_ids == tuple(
        event.id for event in (*failures, approval)
    )


def test_repeated_mfa_rule_requires_at_least_three_failures() -> None:
    failures = tuple(mfa_failure_event(index, index) for index in range(2))

    result = RepeatedMfaFailuresThenApprovalRule().evaluate(
        context_for(mfa_completed_event(), prior=failures)
    )

    assert result.matched is False


def test_repeated_mfa_rule_ignores_non_mfa_login_failures() -> None:
    failures = tuple(
        mfa_failure_event(index, index, reason="invalid_credentials")
        for index in range(3)
    )

    result = RepeatedMfaFailuresThenApprovalRule().evaluate(
        context_for(mfa_completed_event(), prior=failures)
    )

    assert result.matched is False


def test_repeated_mfa_rule_requires_approved_trigger() -> None:
    failures = tuple(mfa_failure_event(index, index) for index in range(3))

    result = RepeatedMfaFailuresThenApprovalRule().evaluate(
        context_for(mfa_completed_event(outcome="denied"), prior=failures)
    )

    assert result.matched is False


def test_repeated_mfa_rule_respects_ten_minute_window() -> None:
    failures = tuple(mfa_failure_event(index, index) for index in range(3))

    result = RepeatedMfaFailuresThenApprovalRule().evaluate(
        context_for(mfa_completed_event(minute=20), prior=failures)
    )

    assert result.matched is False


def password_login_success_event(
    *,
    minute: int = 3,
    authentication_method: str = "password",
    mfa_used: bool = False,
):
    occurred_at = f"2026-10-24T08:{minute:02d}:00+03:00"
    return parse_security_event(
        {
            "id": "30000000-0000-4000-8000-000000000001",
            "event_type": "login_succeeded",
            "occurred_at": occurred_at,
            "received_at": occurred_at,
            "user_id": USER_ID,
            "session_id": SESSION_ID,
            "device_id": NEW_DEVICE_ID,
            "source_ip": "203.0.113.42",
            "geo_country": "US",
            "correlation_id": CORRELATION_ID,
            "payload": {
                "authentication_method": authentication_method,
                "mfa_used": mfa_used,
            },
        }
    )


def invalid_credential_failures(count: int = 3):
    return tuple(
        mfa_failure_event(index + 20, index, reason="invalid_credentials")
        for index in range(count)
    )


def test_repeated_invalid_credentials_then_success_matches() -> None:
    failures = invalid_credential_failures()
    success = password_login_success_event()

    result = RepeatedInvalidCredentialsThenSuccessRule().evaluate(
        context_for(success, prior=failures)
    )

    assert result.matched is True
    assert result.score_delta == 35
    assert result.category is RuleCategory.CONTRADICTION
    assert result.evidence_event_ids == tuple(
        event.id for event in (*failures, success)
    )


def test_repeated_invalid_credentials_rule_requires_three_failures() -> None:
    result = RepeatedInvalidCredentialsThenSuccessRule().evaluate(
        context_for(
            password_login_success_event(),
            prior=invalid_credential_failures(count=2),
        )
    )

    assert result.matched is False


def test_repeated_invalid_credentials_rule_ignores_mfa_failures() -> None:
    mfa_failures = tuple(mfa_failure_event(index, index) for index in range(3))

    result = RepeatedInvalidCredentialsThenSuccessRule().evaluate(
        context_for(password_login_success_event(), prior=mfa_failures)
    )

    assert result.matched is False


@pytest.mark.parametrize(
    ("authentication_method", "mfa_used"),
    [("password_and_otp", True), ("passkey", True)],
)
def test_repeated_invalid_credentials_rule_requires_password_only_success(
    authentication_method: str,
    mfa_used: bool,
) -> None:
    result = RepeatedInvalidCredentialsThenSuccessRule().evaluate(
        context_for(
            password_login_success_event(
                authentication_method=authentication_method,
                mfa_used=mfa_used,
            ),
            prior=invalid_credential_failures(),
        )
    )

    assert result.matched is False


def test_repeated_invalid_credentials_rule_respects_ten_minute_window() -> None:
    result = RepeatedInvalidCredentialsThenSuccessRule().evaluate(
        context_for(
            password_login_success_event(minute=20),
            prior=invalid_credential_failures(),
        )
    )

    assert result.matched is False


def session_login_event(
    *,
    occurred_at: str = "2026-10-24T08:00:00+03:00",
    device_id: str = KNOWN_DEVICE_ID,
    country: str = "TR",
):
    return parse_security_event(
        {
            "id": "40000000-0000-4000-8000-000000000001",
            "event_type": "login_succeeded",
            "occurred_at": occurred_at,
            "received_at": occurred_at,
            "user_id": USER_ID,
            "session_id": SESSION_ID,
            "device_id": device_id,
            "source_ip": "203.0.113.42",
            "geo_country": country,
            "correlation_id": CORRELATION_ID,
            "payload": {
                "authentication_method": "passkey",
                "mfa_used": True,
            },
        }
    )


def test_session_context_switch_before_transfer_matches() -> None:
    login = session_login_event()
    trigger = transfer_event(
        occurred_at="2026-10-24T08:20:00+03:00",
        device_id=NEW_DEVICE_ID,
        country="US",
    )

    result = SessionContextSwitchBeforeTransferRule().evaluate(
        context_for(trigger, prior=(login,))
    )

    assert result.matched is True
    assert result.score_delta == 35
    assert result.category is RuleCategory.CONTRADICTION
    assert result.evidence_event_ids == (login.id, trigger.id)


def test_session_context_switch_requires_both_device_and_country_change() -> None:
    login = session_login_event()
    device_only = transfer_event(
        occurred_at="2026-10-24T08:20:00+03:00",
        device_id=NEW_DEVICE_ID,
        country="TR",
    )
    country_only = transfer_event(
        occurred_at="2026-10-24T08:20:00+03:00",
        device_id=KNOWN_DEVICE_ID,
        country="US",
    )
    rule = SessionContextSwitchBeforeTransferRule()

    assert rule.evaluate(context_for(device_only, prior=(login,))).matched is False
    assert rule.evaluate(context_for(country_only, prior=(login,))).matched is False


def test_session_context_switch_respects_thirty_minute_window() -> None:
    result = SessionContextSwitchBeforeTransferRule().evaluate(
        context_for(
            transfer_event(
                occurred_at="2026-10-24T08:31:00+03:00",
                device_id=NEW_DEVICE_ID,
                country="US",
            ),
            prior=(session_login_event(),),
        )
    )

    assert result.matched is False


def test_session_context_switch_requires_transfer_telemetry() -> None:
    trigger = transfer_event(device_id=None, country=None)  # type: ignore[arg-type]

    result = SessionContextSwitchBeforeTransferRule().evaluate(
        context_for(trigger, prior=(session_login_event(),))
    )

    assert result.matched is False


def test_session_context_switch_requires_transfer_trigger() -> None:
    result = SessionContextSwitchBeforeTransferRule().evaluate(
        context_for(session_login_event())
    )

    assert result.matched is False
