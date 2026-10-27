"""Versioned detection rules shipped with ShadowTrust."""

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

__all__ = [
    "AccountRecoveryDeviceRegistrationRule",
    "NewDeviceRule",
    "PasswordBeneficiaryTransferRule",
    "RecoveryDeviceThenTransferRule",
    "RepeatedMfaFailuresThenApprovalRule",
    "RepeatedInvalidCredentialsThenSuccessRule",
    "SessionContextSwitchBeforeTransferRule",
    "UnusualCountryRule",
]
