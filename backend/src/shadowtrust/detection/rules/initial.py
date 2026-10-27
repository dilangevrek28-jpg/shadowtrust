"""Initial explainable signal and contradiction rules."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import ClassVar

from shadowtrust.detection.context import DetectionContext
from shadowtrust.domain.decisions import RuleCategory, RuleEvaluation
from shadowtrust.domain.events import (
    AuthenticationMethod,
    BeneficiaryAddedEvent,
    DeviceRegisteredEvent,
    DeviceRegistrationMethod,
    LoginFailedEvent,
    LoginFailureReason,
    LoginSucceededEvent,
    MfaChallengeCompletedEvent,
    MfaOutcome,
    PasswordChangedEvent,
    TransferInitiatedEvent,
)


RULE_VERSION = "2026.1"


@dataclass(frozen=True, slots=True)
class NewDeviceRule:
    """Raise risk when the current device is absent from a mature baseline."""

    code: ClassVar[str] = "NEW_DEVICE"
    version: str = RULE_VERSION
    score_delta: int = 15

    def evaluate(self, context: DetectionContext) -> RuleEvaluation:
        device_id = context.trigger_event.device_id
        baseline = context.baseline
        if device_id is None:
            return self._unmatched("The trigger event has no device identifier.")
        if baseline is None or not baseline.known_device_ids:
            return self._unmatched("No known-device history is available for comparison.")
        if any(event.device_id == device_id for event in context.prior_events):
            return self._unmatched("The device was already scored earlier in the session.")
        if device_id in baseline.known_device_ids:
            return self._unmatched("The device is present in the user baseline.")
        return RuleEvaluation(
            rule_code=self.code,
            rule_version=self.version,
            category=RuleCategory.SIGNAL,
            matched=True,
            score_delta=self.score_delta,
            reason="The device is not present in the user baseline.",
            evidence_event_ids=(context.trigger_event.id,),
        )

    def _unmatched(self, reason: str) -> RuleEvaluation:
        return RuleEvaluation(
            rule_code=self.code,
            rule_version=self.version,
            category=RuleCategory.SIGNAL,
            matched=False,
            score_delta=0,
            reason=reason,
        )


@dataclass(frozen=True, slots=True)
class UnusualCountryRule:
    """Raise risk when the event country is absent from a mature baseline."""

    code: ClassVar[str] = "UNUSUAL_COUNTRY"
    version: str = RULE_VERSION
    score_delta: int = 20

    def evaluate(self, context: DetectionContext) -> RuleEvaluation:
        country = context.trigger_event.geo_country
        baseline = context.baseline
        if country is None:
            return self._unmatched("The trigger event has no country information.")
        if baseline is None or not baseline.known_countries:
            return self._unmatched("No country history is available for comparison.")
        if any(event.geo_country == country for event in context.prior_events):
            return self._unmatched("The country was already scored earlier in the session.")
        if country in baseline.known_countries:
            return self._unmatched("The country is present in the user baseline.")
        return RuleEvaluation(
            rule_code=self.code,
            rule_version=self.version,
            category=RuleCategory.SIGNAL,
            matched=True,
            score_delta=self.score_delta,
            reason="The event country is not present in the user baseline.",
            evidence_event_ids=(context.trigger_event.id,),
        )

    def _unmatched(self, reason: str) -> RuleEvaluation:
        return RuleEvaluation(
            rule_code=self.code,
            rule_version=self.version,
            category=RuleCategory.SIGNAL,
            matched=False,
            score_delta=0,
            reason=reason,
        )


@dataclass(frozen=True, slots=True)
class AccountRecoveryDeviceRegistrationRule:
    """Raise risk when a device is registered through account recovery."""

    code: ClassVar[str] = "ACCOUNT_RECOVERY_DEVICE_REGISTRATION"
    version: str = RULE_VERSION
    score_delta: int = 25

    def evaluate(self, context: DetectionContext) -> RuleEvaluation:
        event = context.trigger_event
        matched = (
            isinstance(event, DeviceRegisteredEvent)
            and event.payload.registration_method
            is DeviceRegistrationMethod.RECOVERY_FLOW
        )
        if not matched:
            return RuleEvaluation(
                rule_code=self.code,
                rule_version=self.version,
                category=RuleCategory.SIGNAL,
                matched=False,
                score_delta=0,
                reason="The trigger is not a recovery-flow device registration.",
            )
        return RuleEvaluation(
            rule_code=self.code,
            rule_version=self.version,
            category=RuleCategory.SIGNAL,
            matched=True,
            score_delta=self.score_delta,
            reason="A device was registered through the account recovery flow.",
            evidence_event_ids=(event.id,),
        )


@dataclass(frozen=True, slots=True)
class RecoveryDeviceThenTransferRule:
    """Detect a transfer soon after recovery-flow device registration."""

    code: ClassVar[str] = "RECOVERY_DEVICE_THEN_TRANSFER"
    version: str = RULE_VERSION
    score_delta: int = 40
    window: timedelta = timedelta(minutes=30)

    def evaluate(self, context: DetectionContext) -> RuleEvaluation:
        trigger = context.trigger_event
        if not isinstance(trigger, TransferInitiatedEvent):
            return self._unmatched("The trigger event is not a transfer.")

        candidates = [
            event
            for event in context.prior_events
            if isinstance(event, DeviceRegisteredEvent)
            and event.payload.registration_method
            is DeviceRegistrationMethod.RECOVERY_FLOW
            and timedelta(0) <= trigger.occurred_at - event.occurred_at <= self.window
        ]
        if not candidates:
            return self._unmatched(
                "No recent recovery-flow device registration precedes the transfer."
            )

        registration = max(candidates, key=lambda event: event.occurred_at)
        return RuleEvaluation(
            rule_code=self.code,
            rule_version=self.version,
            category=RuleCategory.CONTRADICTION,
            matched=True,
            score_delta=self.score_delta,
            reason=(
                "A transfer was initiated within 30 minutes of registering a device "
                "through account recovery."
            ),
            evidence_event_ids=(registration.id, trigger.id),
        )

    def _unmatched(self, reason: str) -> RuleEvaluation:
        return RuleEvaluation(
            rule_code=self.code,
            rule_version=self.version,
            category=RuleCategory.CONTRADICTION,
            matched=False,
            score_delta=0,
            reason=reason,
        )



@dataclass(frozen=True, slots=True)
class PasswordBeneficiaryTransferRule:
    """Detect password change, beneficiary creation, and transfer in sequence."""

    code: ClassVar[str] = "PASSWORD_CHANGE_BENEFICIARY_TRANSFER"
    version: str = RULE_VERSION
    score_delta: int = 70
    window: timedelta = timedelta(minutes=15)

    def evaluate(self, context: DetectionContext) -> RuleEvaluation:
        trigger = context.trigger_event
        if not isinstance(trigger, TransferInitiatedEvent):
            return self._unmatched("The trigger event is not a transfer.")

        sequences = []
        for beneficiary in context.prior_events:
            if not isinstance(beneficiary, BeneficiaryAddedEvent):
                continue
            if beneficiary.payload.beneficiary_id != trigger.payload.beneficiary_id:
                continue
            beneficiary_to_transfer = trigger.occurred_at - beneficiary.occurred_at
            if not timedelta(0) <= beneficiary_to_transfer <= self.window:
                continue

            for password_change in context.prior_events:
                if not isinstance(password_change, PasswordChangedEvent):
                    continue
                password_to_beneficiary = (
                    beneficiary.occurred_at - password_change.occurred_at
                )
                password_to_transfer = trigger.occurred_at - password_change.occurred_at
                if (
                    timedelta(0) <= password_to_beneficiary
                    and password_to_transfer <= self.window
                ):
                    sequences.append((password_change, beneficiary))

        if not sequences:
            return self._unmatched(
                "No password-change and matching-beneficiary sequence precedes the transfer."
            )

        password_change, beneficiary = max(
            sequences,
            key=lambda pair: pair[1].occurred_at,
        )
        return RuleEvaluation(
            rule_code=self.code,
            rule_version=self.version,
            category=RuleCategory.CONTRADICTION,
            matched=True,
            score_delta=self.score_delta,
            reason=(
                "A password change was followed by creation of the transfer "
                "beneficiary and a transfer within 15 minutes."
            ),
            evidence_event_ids=(password_change.id, beneficiary.id, trigger.id),
        )

    def _unmatched(self, reason: str) -> RuleEvaluation:
        return RuleEvaluation(
            rule_code=self.code,
            rule_version=self.version,
            category=RuleCategory.CONTRADICTION,
            matched=False,
            score_delta=0,
            reason=reason,
        )



@dataclass(frozen=True, slots=True)
class RepeatedMfaFailuresThenApprovalRule:
    """Detect repeated MFA failures followed by an approval."""

    code: ClassVar[str] = "REPEATED_MFA_FAILURES_THEN_APPROVAL"
    version: str = RULE_VERSION
    score_delta: int = 35
    minimum_failures: int = 3
    window: timedelta = timedelta(minutes=10)

    def evaluate(self, context: DetectionContext) -> RuleEvaluation:
        trigger = context.trigger_event
        if not (
            isinstance(trigger, MfaChallengeCompletedEvent)
            and trigger.payload.outcome is MfaOutcome.APPROVED
        ):
            return self._unmatched("The trigger is not an approved MFA challenge.")

        failures = sorted(
            (
                event
                for event in context.prior_events
                if isinstance(event, LoginFailedEvent)
                and event.payload.reason is LoginFailureReason.MFA_FAILED
                and timedelta(0)
                <= trigger.occurred_at - event.occurred_at
                <= self.window
            ),
            key=lambda event: event.occurred_at,
        )
        if len(failures) < self.minimum_failures:
            return self._unmatched(
                f"Fewer than {self.minimum_failures} recent MFA failures precede approval."
            )

        evidence_failures = failures[-self.minimum_failures :]
        return RuleEvaluation(
            rule_code=self.code,
            rule_version=self.version,
            category=RuleCategory.CONTRADICTION,
            matched=True,
            score_delta=self.score_delta,
            reason=(
                f"An MFA approval followed at least {self.minimum_failures} MFA failures "
                "within 10 minutes."
            ),
            evidence_event_ids=tuple(
                event.id for event in (*evidence_failures, trigger)
            ),
        )

    def _unmatched(self, reason: str) -> RuleEvaluation:
        return RuleEvaluation(
            rule_code=self.code,
            rule_version=self.version,
            category=RuleCategory.CONTRADICTION,
            matched=False,
            score_delta=0,
            reason=reason,
        )


@dataclass(frozen=True, slots=True)
class RepeatedInvalidCredentialsThenSuccessRule:
    """Detect repeated invalid credentials followed by password-only success."""

    code: ClassVar[str] = "REPEATED_INVALID_CREDENTIALS_THEN_SUCCESS"
    version: str = RULE_VERSION
    score_delta: int = 35
    minimum_failures: int = 3
    window: timedelta = timedelta(minutes=10)

    def evaluate(self, context: DetectionContext) -> RuleEvaluation:
        trigger = context.trigger_event
        if not (
            isinstance(trigger, LoginSucceededEvent)
            and trigger.payload.authentication_method is AuthenticationMethod.PASSWORD
            and trigger.payload.mfa_used is False
        ):
            return self._unmatched(
                "The trigger is not a successful password-only login."
            )

        failures = sorted(
            (
                event
                for event in context.prior_events
                if isinstance(event, LoginFailedEvent)
                and event.payload.reason is LoginFailureReason.INVALID_CREDENTIALS
                and timedelta(0)
                <= trigger.occurred_at - event.occurred_at
                <= self.window
            ),
            key=lambda event: event.occurred_at,
        )
        if len(failures) < self.minimum_failures:
            return self._unmatched(
                f"Fewer than {self.minimum_failures} recent invalid-credential "
                "failures precede login success."
            )

        evidence_failures = failures[-self.minimum_failures :]
        return RuleEvaluation(
            rule_code=self.code,
            rule_version=self.version,
            category=RuleCategory.CONTRADICTION,
            matched=True,
            score_delta=self.score_delta,
            reason=(
                f"A password-only login succeeded after at least "
                f"{self.minimum_failures} invalid-credential failures within "
                "10 minutes."
            ),
            evidence_event_ids=tuple(
                event.id for event in (*evidence_failures, trigger)
            ),
        )

    def _unmatched(self, reason: str) -> RuleEvaluation:
        return RuleEvaluation(
            rule_code=self.code,
            rule_version=self.version,
            category=RuleCategory.CONTRADICTION,
            matched=False,
            score_delta=0,
            reason=reason,
        )



@dataclass(frozen=True, slots=True)
class SessionContextSwitchBeforeTransferRule:
    """Detect a device and country switch inside an authenticated session."""

    code: ClassVar[str] = "SESSION_CONTEXT_SWITCH_BEFORE_TRANSFER"
    version: str = RULE_VERSION
    score_delta: int = 35
    window: timedelta = timedelta(minutes=30)

    def evaluate(self, context: DetectionContext) -> RuleEvaluation:
        trigger = context.trigger_event
        if not isinstance(trigger, TransferInitiatedEvent):
            return self._unmatched("The trigger event is not a transfer.")
        if trigger.device_id is None or trigger.geo_country is None:
            return self._unmatched(
                "The transfer lacks device or country context for comparison."
            )

        suspicious_logins = [
            event
            for event in context.prior_events
            if isinstance(event, LoginSucceededEvent)
            and event.device_id is not None
            and event.geo_country is not None
            and event.device_id != trigger.device_id
            and event.geo_country != trigger.geo_country
            and timedelta(0)
            <= trigger.occurred_at - event.occurred_at
            <= self.window
        ]
        if not suspicious_logins:
            return self._unmatched(
                "No recent login has both a different device and country."
            )

        login = max(suspicious_logins, key=lambda event: event.occurred_at)
        return RuleEvaluation(
            rule_code=self.code,
            rule_version=self.version,
            category=RuleCategory.CONTRADICTION,
            matched=True,
            score_delta=self.score_delta,
            reason=(
                "A transfer used a different device and country than the recent "
                "successful login in the same session."
            ),
            evidence_event_ids=(login.id, trigger.id),
        )

    def _unmatched(self, reason: str) -> RuleEvaluation:
        return RuleEvaluation(
            rule_code=self.code,
            rule_version=self.version,
            category=RuleCategory.CONTRADICTION,
            matched=False,
            score_delta=0,
            reason=reason,
        )
