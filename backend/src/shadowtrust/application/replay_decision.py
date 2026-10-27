"""Rebuild a historical detection context and verify decision reproducibility."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from uuid import UUID

from sqlalchemy.orm import Session, sessionmaker

from shadowtrust.detection.context import DetectionContext
from shadowtrust.detection.engine import DetectionEngine
from shadowtrust.domain.decisions import DetectionDecision
from shadowtrust.domain.events import SecurityEvent
from shadowtrust.persistence.database import transactional_session
from shadowtrust.persistence.repositories import (
    DetectionDecisionRepository,
    SecurityEventRepository,
    UserBaselineRepository,
)


class DecisionReplayNotFoundError(LookupError):
    """The requested historical decision does not exist."""


class DecisionReplayUnavailableError(RuntimeError):
    """Required historical inputs are no longer available."""


class DecisionReplayStatus(StrEnum):
    REPRODUCED = "reproduced"
    DRIFTED = "drifted"
    INCOMPATIBLE = "incompatible"


@dataclass(frozen=True, slots=True)
class DecisionReplayResult:
    status: DecisionReplayStatus
    original_decision: DetectionDecision
    replayed_decision: DetectionDecision | None
    differences: tuple[str, ...]


class ReplayDecisionService:
    """Replay only when the active engine matches the recorded rule identity."""

    _COMPARISON_FIELDS = (
        "session_id",
        "trigger_event_id",
        "risk_before",
        "risk_after",
        "evaluations",
        "recommended_actions",
        "explanation",
        "rule_set_version",
        "engine_version",
        "baseline_version",
    )

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        engine: DetectionEngine,
    ) -> None:
        self._session_factory = session_factory
        self._engine = engine

    def replay(self, decision_id: UUID) -> DecisionReplayResult:
        with transactional_session(self._session_factory) as session:
            decision_repository = DetectionDecisionRepository(session)
            event_repository = SecurityEventRepository(session)
            baseline_repository = UserBaselineRepository(session)

            original = decision_repository.get(decision_id)
            if original is None:
                raise DecisionReplayNotFoundError("Detection decision not found.")

            compatibility_differences = self._compatibility_differences(original)
            if compatibility_differences:
                return DecisionReplayResult(
                    status=DecisionReplayStatus.INCOMPATIBLE,
                    original_decision=original,
                    replayed_decision=None,
                    differences=compatibility_differences,
                )

            trigger = event_repository.get(original.trigger_event_id)
            if trigger is None:
                raise DecisionReplayUnavailableError(
                    "The replay trigger event is no longer available."
                )

            baseline = None
            if original.baseline_version is not None:
                baseline = baseline_repository.get(
                    trigger.user_id,
                    original.baseline_version,
                )
                if baseline is None:
                    raise DecisionReplayUnavailableError(
                        "The recorded baseline version is no longer available."
                    )

            prior_events = tuple(
                event
                for event in event_repository.list_for_session(original.session_id)
                if self._precedes(event, trigger)
            )
            replayed = self._engine.evaluate(
                DetectionContext(
                    trigger_event=trigger,
                    prior_events=prior_events,
                    risk_before=original.risk_before,
                    baseline=baseline,
                    baseline_version=original.baseline_version,
                )
            )
            differences = self._decision_differences(original, replayed)
            return DecisionReplayResult(
                status=(
                    DecisionReplayStatus.DRIFTED
                    if differences
                    else DecisionReplayStatus.REPRODUCED
                ),
                original_decision=original,
                replayed_decision=replayed,
                differences=differences,
            )

    def _compatibility_differences(
        self,
        original: DetectionDecision,
    ) -> tuple[str, ...]:
        differences: list[str] = []
        if original.engine_version != self._engine.engine_version:
            differences.append("engine_version")
        if original.rule_set_version != self._engine.rule_set_version:
            differences.append("rule_set_version")
        stored_rules = tuple(
            (evaluation.rule_code, evaluation.rule_version)
            for evaluation in original.evaluations
        )
        active_rules = tuple((rule.code, rule.version) for rule in self._engine.rules)
        if stored_rules != active_rules:
            differences.append("rule_versions")
        return tuple(differences)

    @classmethod
    def _decision_differences(
        cls,
        original: DetectionDecision,
        replayed: DetectionDecision,
    ) -> tuple[str, ...]:
        return tuple(
            field
            for field in cls._COMPARISON_FIELDS
            if getattr(original, field) != getattr(replayed, field)
        )

    @staticmethod
    def _precedes(candidate: SecurityEvent, trigger: SecurityEvent) -> bool:
        if candidate.id == trigger.id:
            return False
        return (
            candidate.occurred_at,
            candidate.received_at,
            str(candidate.id),
        ) < (
            trigger.occurred_at,
            trigger.received_at,
            str(trigger.id),
        )
