"""Canonical, versioned security-event contract for ShadowTrust.

These models validate facts emitted by the synthetic banking environment. They
must not contain risk scores, trust decisions, or ground-truth attack labels;
those belong to later processing and evaluation layers.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from decimal import Decimal
from enum import StrEnum
from typing import Annotated, Literal
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyAddress,
    TypeAdapter,
    field_validator,
    model_validator,
)


MAX_CLOCK_SKEW = timedelta(minutes=5)


class AuthenticationMethod(StrEnum):
    PASSWORD = "password"
    PASSWORD_AND_OTP = "password_and_otp"
    PASSKEY = "passkey"


class LoginFailureReason(StrEnum):
    INVALID_CREDENTIALS = "invalid_credentials"
    LOCKED_ACCOUNT = "locked_account"
    MFA_FAILED = "mfa_failed"


class MfaOutcome(StrEnum):
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"


class PasswordChangeMethod(StrEnum):
    AUTHENTICATED_SESSION = "authenticated_session"
    ACCOUNT_RECOVERY = "account_recovery"


class ContactField(StrEnum):
    EMAIL = "email"
    PHONE = "phone"
    ADDRESS = "address"


class SessionRevocationReason(StrEnum):
    USER_REQUEST = "user_request"
    SECURITY_POLICY = "security_policy"
    ANALYST_ACTION = "analyst_action"


class DeviceRegistrationMethod(StrEnum):
    MFA_VERIFIED = "mfa_verified"
    RECOVERY_FLOW = "recovery_flow"


class EventPayload(BaseModel):
    """Base payload policy shared by every event type."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class LoginSucceededPayload(EventPayload):
    authentication_method: AuthenticationMethod
    mfa_used: bool


class LoginFailedPayload(EventPayload):
    reason: LoginFailureReason


class MfaChallengeCompletedPayload(EventPayload):
    outcome: MfaOutcome


class PasswordChangedPayload(EventPayload):
    method: PasswordChangeMethod


class ContactInformationChangedPayload(EventPayload):
    changed_fields: set[ContactField] = Field(min_length=1)


class BeneficiaryAddedPayload(EventPayload):
    beneficiary_id: UUID
    bank_country: str = Field(pattern=r"^[A-Z]{2}$")

    @field_validator("bank_country", mode="before")
    @classmethod
    def normalize_country(cls, value: object) -> object:
        return value.upper() if isinstance(value, str) else value


class TransferInitiatedPayload(EventPayload):
    transaction_id: UUID
    beneficiary_id: UUID
    amount: Decimal = Field(gt=0, max_digits=18, decimal_places=2)
    currency: str = Field(pattern=r"^[A-Z]{3}$")

    @field_validator("currency", mode="before")
    @classmethod
    def normalize_currency(cls, value: object) -> object:
        return value.upper() if isinstance(value, str) else value


class TransferConfirmedPayload(EventPayload):
    transaction_id: UUID


class SessionRevokedPayload(EventPayload):
    reason: SessionRevocationReason


class DeviceRegisteredPayload(EventPayload):
    registration_method: DeviceRegistrationMethod


class SecurityEventBase(BaseModel):
    """Fields present in every canonical security event."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: UUID
    schema_version: Literal["1.0"] = "1.0"
    occurred_at: datetime
    received_at: datetime
    user_id: UUID
    session_id: UUID | None = None
    device_id: UUID | None = None
    source_ip: IPvAnyAddress | None = None
    geo_country: str | None = Field(default=None, pattern=r"^[A-Z]{2}$")
    correlation_id: UUID

    @field_validator("occurred_at", "received_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must include a timezone offset")
        return value

    @field_validator("geo_country", mode="before")
    @classmethod
    def normalize_geo_country(cls, value: object) -> object:
        return value.upper() if isinstance(value, str) else value

    @model_validator(mode="after")
    def validate_event_time(self) -> SecurityEventBase:
        if self.occurred_at > self.received_at + MAX_CLOCK_SKEW:
            raise ValueError("occurred_at is too far after received_at")
        return self

    def require_context(self, *field_names: str) -> None:
        missing = [name for name in field_names if getattr(self, name) is None]
        if missing:
            raise ValueError(f"event requires context fields: {', '.join(missing)}")


class LoginSucceededEvent(SecurityEventBase):
    event_type: Literal["login_succeeded"]
    payload: LoginSucceededPayload

    @model_validator(mode="after")
    def validate_context(self) -> LoginSucceededEvent:
        self.require_context("session_id", "device_id")
        return self


class LoginFailedEvent(SecurityEventBase):
    event_type: Literal["login_failed"]
    payload: LoginFailedPayload


class MfaChallengeCompletedEvent(SecurityEventBase):
    event_type: Literal["mfa_challenge_completed"]
    payload: MfaChallengeCompletedPayload

    @model_validator(mode="after")
    def validate_context(self) -> MfaChallengeCompletedEvent:
        self.require_context("session_id")
        return self


class PasswordChangedEvent(SecurityEventBase):
    event_type: Literal["password_changed"]
    payload: PasswordChangedPayload

    @model_validator(mode="after")
    def validate_context(self) -> PasswordChangedEvent:
        self.require_context("session_id")
        return self


class ContactInformationChangedEvent(SecurityEventBase):
    event_type: Literal["contact_information_changed"]
    payload: ContactInformationChangedPayload

    @model_validator(mode="after")
    def validate_context(self) -> ContactInformationChangedEvent:
        self.require_context("session_id")
        return self


class BeneficiaryAddedEvent(SecurityEventBase):
    event_type: Literal["beneficiary_added"]
    payload: BeneficiaryAddedPayload

    @model_validator(mode="after")
    def validate_context(self) -> BeneficiaryAddedEvent:
        self.require_context("session_id")
        return self


class TransferInitiatedEvent(SecurityEventBase):
    event_type: Literal["transfer_initiated"]
    payload: TransferInitiatedPayload

    @model_validator(mode="after")
    def validate_context(self) -> TransferInitiatedEvent:
        self.require_context("session_id")
        return self


class TransferConfirmedEvent(SecurityEventBase):
    event_type: Literal["transfer_confirmed"]
    payload: TransferConfirmedPayload

    @model_validator(mode="after")
    def validate_context(self) -> TransferConfirmedEvent:
        self.require_context("session_id")
        return self


class SessionRevokedEvent(SecurityEventBase):
    event_type: Literal["session_revoked"]
    payload: SessionRevokedPayload

    @model_validator(mode="after")
    def validate_context(self) -> SessionRevokedEvent:
        self.require_context("session_id")
        return self


class DeviceRegisteredEvent(SecurityEventBase):
    event_type: Literal["device_registered"]
    payload: DeviceRegisteredPayload

    @model_validator(mode="after")
    def validate_context(self) -> DeviceRegisteredEvent:
        self.require_context("session_id", "device_id")
        return self


SecurityEvent = Annotated[
    LoginSucceededEvent
    | LoginFailedEvent
    | MfaChallengeCompletedEvent
    | PasswordChangedEvent
    | ContactInformationChangedEvent
    | BeneficiaryAddedEvent
    | TransferInitiatedEvent
    | TransferConfirmedEvent
    | SessionRevokedEvent
    | DeviceRegisteredEvent,
    Field(discriminator="event_type"),
]

_SECURITY_EVENT_ADAPTER = TypeAdapter(SecurityEvent)


def parse_security_event(raw_event: object) -> SecurityEvent:
    """Parse untrusted input into one exact, immutable event subtype."""

    return _SECURITY_EVENT_ADAPTER.validate_python(raw_event)
