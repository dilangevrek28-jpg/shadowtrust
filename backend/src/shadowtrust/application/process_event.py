"""Application service for idempotent event ingestion and detection."""

from __future__ import annotations

from dataclasses import dataclass
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


class EventConflictError(ValueError):
    """Raised when an existing event ID is reused with different content."""


class OutOfOrderEventError(ValueError):
    """Raised when an event would require trust-timeline recalculation."""


@dataclass(frozen=True, slots=True)
class ProcessEventResult:
    event: SecurityEvent
    decision: DetectionDecision | None
    created: bool


class ProcessSecurityEventService:
    """Coordinate persistence and detection as one atomic unit of work."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        engine: DetectionEngine,
    ) -> None:
        self._session_factory = session_factory
        self._engine = engine

    def process(self, event: SecurityEvent) -> ProcessEventResult:
        with transactional_session(self._session_factory) as session:
            event_repository = SecurityEventRepository(session)
            decision_repository = DetectionDecisionRepository(session)
            baseline_repository = UserBaselineRepository(session)

            existing_event = event_repository.get(event.id)
            if existing_event is not None:
                if existing_event != event:
                    raise EventConflictError(
                        f"event ID {event.id} already exists with different content"
                    )
                return ProcessEventResult(
                    event=existing_event,
                    decision=decision_repository.get_for_trigger(event.id),
                    created=False,
                )

            if event.session_id is None:
                event_repository.add(event)
                return ProcessEventResult(event=event, decision=None, created=True)

            prior_events = event_repository.list_for_session(event.session_id)
            if prior_events and prior_events[-1].occurred_at > event.occurred_at:
                raise OutOfOrderEventError(
                    f"event {event.id} occurred before the latest persisted "
                    f"session event {prior_events[-1].id}"
                )

            latest_decision = decision_repository.get_latest_for_session(
                event.session_id
            )
            baseline = baseline_repository.get_latest(event.user_id)
            context = DetectionContext(
                trigger_event=event,
                prior_events=prior_events,
                risk_before=(
                    latest_decision.risk_after if latest_decision is not None else 0
                ),
                baseline=baseline,
            )
            decision = self._engine.evaluate(context)

            event_repository.add(event)
            decision_repository.add(decision)
            return ProcessEventResult(event=event, decision=decision, created=True)
