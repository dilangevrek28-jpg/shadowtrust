"""Deterministic synthetic scenarios for development and evaluation."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from uuid import UUID, uuid5

from pydantic import BaseModel, ConfigDict, Field, model_validator

from shadowtrust.domain.baselines import UserBaseline
from shadowtrust.domain.events import SecurityEvent, parse_security_event


SYNTHETIC_NAMESPACE = UUID("76db00aa-397f-4ba6-9dc4-ce0a65e8ad5a")
ISTANBUL_TIMEZONE = timezone(timedelta(hours=3))


class ScenarioGroundTruth(StrEnum):
    NORMAL = "normal"
    ATO = "ato"


class DatasetSplit(StrEnum):
    DEVELOPMENT = "development"
    EVALUATION = "evaluation"


class SyntheticScenario(BaseModel):
    """Labeled evaluation envelope; labels never enter canonical events."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: UUID
    name: str = Field(min_length=1, max_length=80)
    description: str = Field(min_length=1, max_length=500)
    split: DatasetSplit
    ground_truth: ScenarioGroundTruth
    baseline: UserBaseline
    events: tuple[SecurityEvent, ...] = Field(min_length=1)
    attack_start_event_id: UUID | None = None

    @model_validator(mode="after")
    def validate_scenario(self) -> SyntheticScenario:
        event_ids = [event.id for event in self.events]
        if len(set(event_ids)) != len(event_ids):
            raise ValueError("scenario event ids must be unique")
        if any(event.user_id != self.baseline.user_id for event in self.events):
            raise ValueError("scenario events and baseline must belong to one user")
        event_times = [event.occurred_at for event in self.events]
        if event_times != sorted(event_times):
            raise ValueError("scenario events must be ordered by occurred_at")

        if self.ground_truth is ScenarioGroundTruth.NORMAL:
            if self.attack_start_event_id is not None:
                raise ValueError("normal scenario cannot have an attack start event")
        elif self.attack_start_event_id not in set(event_ids):
            raise ValueError("ATO attack start must reference an event in the scenario")
        return self


def _stable_id(*parts: object) -> UUID:
    """Create repeatable UUIDs without randomness or customer identifiers."""

    return uuid5(SYNTHETIC_NAMESPACE, ":".join(str(part) for part in parts))


@dataclass(slots=True)
class _ScenarioBuilder:
    """Small internal factory that keeps scenario event fields consistent."""

    name: str
    day_offset: int
    events: list[SecurityEvent] = field(default_factory=list)

    @property
    def base_time(self) -> datetime:
        return datetime(2026, 1, 15, 9, 0, tzinfo=ISTANBUL_TIMEZONE) + timedelta(
            days=self.day_offset
        )

    @property
    def user_id(self) -> UUID:
        return _stable_id(self.name, "user")

    @property
    def session_id(self) -> UUID:
        return _stable_id(self.name, "session")

    @property
    def known_device_id(self) -> UUID:
        return _stable_id(self.name, "known-device")

    @property
    def new_device_id(self) -> UUID:
        return _stable_id(self.name, "new-device")

    @property
    def beneficiary_id(self) -> UUID:
        return _stable_id(self.name, "beneficiary")

    def baseline(self) -> UserBaseline:
        return UserBaseline(
            user_id=self.user_id,
            version="baseline-1",
            generated_at=self.base_time - timedelta(days=30),
            sample_size=120,
            known_device_ids={self.known_device_id},
            known_countries={"TR"},
        )

    def add(
        self,
        event_type: str,
        payload: dict[str, object],
        *,
        minute: int,
        device_id: UUID | None = None,
        country: str = "TR",
    ) -> SecurityEvent:
        occurred_at = self.base_time + timedelta(minutes=minute)
        event = parse_security_event(
            {
                "id": _stable_id(self.name, len(self.events), event_type),
                "schema_version": "1.0",
                "event_type": event_type,
                "occurred_at": occurred_at,
                "received_at": occurred_at + timedelta(seconds=1),
                "user_id": self.user_id,
                "session_id": self.session_id,
                "device_id": device_id or self.known_device_id,
                "source_ip": f"198.51.100.{10 + self.day_offset}",
                "geo_country": country,
                "correlation_id": _stable_id(self.name, "correlation"),
                "payload": payload,
            }
        )
        self.events.append(event)
        return event

    def build(
        self,
        *,
        description: str,
        split: DatasetSplit,
        ground_truth: ScenarioGroundTruth,
        attack_start_index: int | None = None,
    ) -> SyntheticScenario:
        attack_start_event_id = (
            self.events[attack_start_index].id
            if attack_start_index is not None
            else None
        )
        return SyntheticScenario(
            id=_stable_id(self.name, "scenario"),
            name=self.name,
            description=description,
            split=split,
            ground_truth=ground_truth,
            baseline=self.baseline(),
            events=tuple(self.events),
            attack_start_event_id=attack_start_event_id,
        )


def _normal_regular_login() -> SyntheticScenario:
    builder = _ScenarioBuilder("normal_regular_login", 0)
    builder.add(
        "login_succeeded",
        {"authentication_method": "password_and_otp", "mfa_used": True},
        minute=0,
    )
    return builder.build(
        description="Known device and country during a routine login.",
        split=DatasetSplit.DEVELOPMENT,
        ground_truth=ScenarioGroundTruth.NORMAL,
    )


def _normal_travel_with_mfa() -> SyntheticScenario:
    builder = _ScenarioBuilder("normal_travel_with_mfa", 1)
    builder.add("mfa_challenge_completed", {"outcome": "approved"}, minute=0, country="DE")
    builder.add(
        "login_succeeded",
        {"authentication_method": "password_and_otp", "mfa_used": True},
        minute=1,
        country="DE",
    )
    return builder.build(
        description="Known device used abroad with successful strong verification.",
        split=DatasetSplit.DEVELOPMENT,
        ground_truth=ScenarioGroundTruth.NORMAL,
    )


def _normal_new_phone() -> SyntheticScenario:
    builder = _ScenarioBuilder("normal_new_phone", 2)
    builder.add("mfa_challenge_completed", {"outcome": "approved"}, minute=0)
    builder.add(
        "device_registered",
        {"registration_method": "mfa_verified"},
        minute=1,
        device_id=builder.new_device_id,
    )
    builder.add(
        "login_succeeded",
        {"authentication_method": "password_and_otp", "mfa_used": True},
        minute=2,
        device_id=builder.new_device_id,
    )
    return builder.build(
        description="A legitimate new phone is registered after MFA.",
        split=DatasetSplit.DEVELOPMENT,
        ground_truth=ScenarioGroundTruth.NORMAL,
    )


def _normal_high_value_transfer() -> SyntheticScenario:
    builder = _ScenarioBuilder("normal_high_value_transfer", 3)
    builder.add(
        "login_succeeded",
        {"authentication_method": "passkey", "mfa_used": True},
        minute=0,
    )
    builder.add(
        "transfer_initiated",
        {
            "transaction_id": _stable_id(builder.name, "transaction"),
            "beneficiary_id": builder.beneficiary_id,
            "amount": "25000.00",
            "currency": "TRY",
        },
        minute=5,
    )
    return builder.build(
        description="A high-value transfer from the usual device and country.",
        split=DatasetSplit.EVALUATION,
        ground_truth=ScenarioGroundTruth.NORMAL,
    )


def _normal_password_change() -> SyntheticScenario:
    builder = _ScenarioBuilder("normal_password_change", 4)
    builder.add(
        "login_succeeded",
        {"authentication_method": "passkey", "mfa_used": True},
        minute=0,
    )
    builder.add(
        "password_changed",
        {"method": "authenticated_session"},
        minute=3,
    )
    return builder.build(
        description="A password change from a strongly authenticated normal session.",
        split=DatasetSplit.EVALUATION,
        ground_truth=ScenarioGroundTruth.NORMAL,
    )


def _ato_credential_stuffing_transfer() -> SyntheticScenario:
    builder = _ScenarioBuilder("ato_credential_stuffing_transfer", 5)
    for minute in range(3):
        builder.add(
            "login_failed",
            {"reason": "invalid_credentials"},
            minute=minute,
            device_id=builder.new_device_id,
            country="US",
        )
    builder.add(
        "login_succeeded",
        {"authentication_method": "password", "mfa_used": False},
        minute=3,
        device_id=builder.new_device_id,
        country="US",
    )
    builder.add(
        "beneficiary_added",
        {"beneficiary_id": builder.beneficiary_id, "bank_country": "US"},
        minute=5,
        device_id=builder.new_device_id,
        country="US",
    )
    builder.add(
        "transfer_initiated",
        {
            "transaction_id": _stable_id(builder.name, "transaction"),
            "beneficiary_id": builder.beneficiary_id,
            "amount": "18000.00",
            "currency": "TRY",
        },
        minute=6,
        device_id=builder.new_device_id,
        country="US",
    )
    return builder.build(
        description="Credential attempts lead to login, beneficiary creation, and transfer.",
        split=DatasetSplit.DEVELOPMENT,
        ground_truth=ScenarioGroundTruth.ATO,
        attack_start_index=0,
    )

def _ato_session_hijacking() -> SyntheticScenario:
    builder = _ScenarioBuilder("ato_session_hijacking", 6)
    builder.add(
        "login_succeeded",
        {"authentication_method": "passkey", "mfa_used": True},
        minute=0,
    )
    builder.add(
        "transfer_initiated",
        {
            "transaction_id": _stable_id(builder.name, "transaction"),
            "beneficiary_id": builder.beneficiary_id,
            "amount": "9500.00",
            "currency": "TRY",
        },
        minute=10,
        device_id=builder.new_device_id,
        country="US",
    )
    return builder.build(
        description="An authenticated session changes device and country before a transfer.",
        split=DatasetSplit.DEVELOPMENT,
        ground_truth=ScenarioGroundTruth.ATO,
        attack_start_index=1,
    )


def _ato_mfa_fatigue() -> SyntheticScenario:
    builder = _ScenarioBuilder("ato_mfa_fatigue", 7)
    for minute in range(3):
        builder.add(
            "login_failed",
            {"reason": "mfa_failed"},
            minute=minute,
            device_id=builder.new_device_id,
            country="US",
        )
    builder.add(
        "mfa_challenge_completed",
        {"outcome": "approved"},
        minute=3,
        device_id=builder.new_device_id,
        country="US",
    )
    builder.add(
        "contact_information_changed",
        {"changed_fields": ["email", "phone"]},
        minute=4,
        device_id=builder.new_device_id,
        country="US",
    )
    builder.add(
        "transfer_initiated",
        {
            "transaction_id": _stable_id(builder.name, "transaction"),
            "beneficiary_id": builder.beneficiary_id,
            "amount": "7200.00",
            "currency": "TRY",
        },
        minute=6,
        device_id=builder.new_device_id,
        country="US",
    )
    return builder.build(
        description="Repeated MFA failures precede approval, profile changes, and transfer.",
        split=DatasetSplit.DEVELOPMENT,
        ground_truth=ScenarioGroundTruth.ATO,
        attack_start_index=0,
    )


def _ato_trusted_device_misuse() -> SyntheticScenario:
    builder = _ScenarioBuilder("ato_trusted_device_misuse", 8)
    builder.add(
        "login_succeeded",
        {"authentication_method": "password", "mfa_used": False},
        minute=0,
    )
    builder.add(
        "password_changed",
        {"method": "authenticated_session"},
        minute=2,
    )
    builder.add(
        "beneficiary_added",
        {"beneficiary_id": builder.beneficiary_id, "bank_country": "TR"},
        minute=3,
    )
    builder.add(
        "transfer_initiated",
        {
            "transaction_id": _stable_id(builder.name, "transaction"),
            "beneficiary_id": builder.beneficiary_id,
            "amount": "4900.00",
            "currency": "TRY",
        },
        minute=4,
    )
    return builder.build(
        description="A trusted device performs a suspicious account-change sequence.",
        split=DatasetSplit.DEVELOPMENT,
        ground_truth=ScenarioGroundTruth.ATO,
        attack_start_index=1,
    )


def _ato_recovery_device_transfer() -> SyntheticScenario:
    builder = _ScenarioBuilder("ato_recovery_device_transfer", 9)
    builder.add(
        "device_registered",
        {"registration_method": "recovery_flow"},
        minute=0,
        device_id=builder.new_device_id,
        country="US",
    )
    builder.add(
        "login_succeeded",
        {"authentication_method": "password", "mfa_used": False},
        minute=1,
        device_id=builder.new_device_id,
        country="US",
    )
    builder.add(
        "beneficiary_added",
        {"beneficiary_id": builder.beneficiary_id, "bank_country": "US"},
        minute=5,
        device_id=builder.new_device_id,
        country="US",
    )
    builder.add(
        "transfer_initiated",
        {
            "transaction_id": _stable_id(builder.name, "transaction"),
            "beneficiary_id": builder.beneficiary_id,
            "amount": "12000.00",
            "currency": "TRY",
        },
        minute=20,
        device_id=builder.new_device_id,
        country="US",
    )
    return builder.build(
        description="Recovery device registration is followed by a rapid transfer.",
        split=DatasetSplit.EVALUATION,
        ground_truth=ScenarioGroundTruth.ATO,
        attack_start_index=0,
    )

def generate_scenarios() -> tuple[SyntheticScenario, ...]:
    """Return the v1 corpus with five normal and six ATO scenarios."""

    return (
        _normal_regular_login(),
        _normal_travel_with_mfa(),
        _normal_new_phone(),
        _normal_high_value_transfer(),
        _normal_password_change(),
        _ato_credential_stuffing_transfer(),
        _ato_session_hijacking(),
        _ato_mfa_fatigue(),
        _ato_mfa_fatigue_holdout(),
        _ato_trusted_device_misuse(),
        _ato_recovery_device_transfer(),
    )



def _ato_mfa_fatigue_holdout() -> SyntheticScenario:
    builder = _ScenarioBuilder("ato_mfa_fatigue_holdout", 10)
    for minute in range(5):
        builder.add(
            "login_failed",
            {"reason": "mfa_failed"},
            minute=minute,
            device_id=builder.new_device_id,
            country="NL",
        )
    builder.add(
        "mfa_challenge_completed",
        {"outcome": "approved"},
        minute=5,
        device_id=builder.new_device_id,
        country="NL",
    )
    builder.add(
        "contact_information_changed",
        {"changed_fields": ["phone"]},
        minute=6,
        device_id=builder.new_device_id,
        country="NL",
    )
    builder.add(
        "transfer_initiated",
        {
            "transaction_id": _stable_id(builder.name, "transaction"),
            "beneficiary_id": builder.beneficiary_id,
            "amount": "6400.00",
            "currency": "TRY",
        },
        minute=9,
        device_id=builder.new_device_id,
        country="NL",
    )
    return builder.build(
        description="A holdout MFA-fatigue variant with five failures before approval.",
        split=DatasetSplit.EVALUATION,
        ground_truth=ScenarioGroundTruth.ATO,
        attack_start_index=0,
    )
