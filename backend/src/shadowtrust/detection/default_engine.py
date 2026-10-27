"""Construction of the versioned default ShadowTrust rule set."""

from __future__ import annotations

from collections.abc import Callable
from uuid import UUID, uuid4

from shadowtrust.detection.engine import DetectionEngine
from shadowtrust.detection.rules import (
    AccountRecoveryDeviceRegistrationRule,
    NewDeviceRule,
    PasswordBeneficiaryTransferRule,
    RecoveryDeviceThenTransferRule,
    RepeatedInvalidCredentialsThenSuccessRule,
    RepeatedMfaFailuresThenApprovalRule,
    SessionContextSwitchBeforeTransferRule,
    UnusualCountryRule,
)


DEFAULT_RULE_SET_VERSION = "2026.5"
DEFAULT_ENGINE_VERSION = "0.1.0"


def build_default_detection_engine(
    *,
    decision_id_factory: Callable[[], UUID] = uuid4,
) -> DetectionEngine:
    """Build the ordered, production-default explainable rule set."""

    return DetectionEngine(
        rules=(
            NewDeviceRule(),
            UnusualCountryRule(),
            AccountRecoveryDeviceRegistrationRule(),
            RecoveryDeviceThenTransferRule(),
            PasswordBeneficiaryTransferRule(),
            RepeatedMfaFailuresThenApprovalRule(),
            RepeatedInvalidCredentialsThenSuccessRule(),
            SessionContextSwitchBeforeTransferRule(),
        ),
        rule_set_version=DEFAULT_RULE_SET_VERSION,
        engine_version=DEFAULT_ENGINE_VERSION,
        decision_id_factory=decision_id_factory,
    )
