"""Thin HTTP routes for ingesting and reading security events."""

import logging

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session, sessionmaker

from shadowtrust.api.dependencies import (
    get_event_service,
    get_metrics_registry,
    get_session_factory,
    require_analyst_access,
    require_event_ingestion_access,
)
from shadowtrust.api.schemas import (
    ErrorResponse,
    ProcessEventResponse,
    SessionTimelineItem,
    SessionTimelineResponse,
)
from shadowtrust.application import ProcessSecurityEventService
from shadowtrust.domain.events import SecurityEvent
from shadowtrust.observability import log_structured
from shadowtrust.observability import MetricsRegistry
from shadowtrust.persistence import (
    DetectionDecisionRepository,
    SecurityEventRepository,
    transactional_session,
)


logger = logging.getLogger("shadowtrust.security_events")
router = APIRouter(prefix="/api/v1", tags=["security-events"])


@router.post(
    "/events",
    response_model=ProcessEventResponse,
    status_code=status.HTTP_201_CREATED,
    responses={409: {"model": ErrorResponse}},
)
def process_event(
    event: SecurityEvent,
    response: Response,
    service: Annotated[ProcessSecurityEventService, Depends(get_event_service)],
    metrics: Annotated[MetricsRegistry, Depends(get_metrics_registry)],
    _access: Annotated[None, Depends(require_event_ingestion_access)],
) -> ProcessEventResponse:
    result = service.process(event)
    decision = result.decision
    metrics.increment(
        "shadowtrust_events_processed_total",
        outcome="created" if result.created else "replayed",
    )
    if decision is not None and result.created:
        metrics.increment(
            "shadowtrust_decisions_total",
            risk_level=decision.risk_level.value,
        )
    log_structured(
        logger,
        logging.INFO,
        "security_event_processed",
        event_id=str(result.event.id),
        event_type=result.event.event_type,
        session_id=(
            str(result.event.session_id) if result.event.session_id else None
        ),
        created=result.created,
        decision_id=str(decision.id) if decision else None,
        risk_before=decision.risk_before if decision else None,
        risk_after=decision.risk_after if decision else None,
        risk_level=decision.risk_level.value if decision else None,
        recommended_actions=(
            [action.value for action in decision.recommended_actions]
            if decision
            else []
        ),
        matched_rules=(
            [item.rule_code for item in decision.evaluations if item.matched]
            if decision
            else []
        ),
    )
    if not result.created:
        response.status_code = status.HTTP_200_OK
    return ProcessEventResponse(
        created=result.created,
        event=result.event,
        decision=result.decision,
    )


@router.get(
    "/events/{event_id}",
    response_model=SecurityEvent,
    responses={404: {"model": ErrorResponse}},
)
def get_event(
    event_id: UUID,
    session_factory: Annotated[
        sessionmaker[Session], Depends(get_session_factory)
    ],
    _access: Annotated[None, Depends(require_analyst_access)],
) -> SecurityEvent:
    with transactional_session(session_factory) as session:
        event = SecurityEventRepository(session).get(event_id)
    if event is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "event_not_found", "message": "Security event not found."},
        )
    return event


@router.get(
    "/sessions/{session_id}/timeline",
    response_model=SessionTimelineResponse,
)
def get_session_timeline(
    session_id: UUID,
    session_factory: Annotated[
        sessionmaker[Session], Depends(get_session_factory)
    ],
    _access: Annotated[None, Depends(require_analyst_access)],
) -> SessionTimelineResponse:
    with transactional_session(session_factory) as session:
        events = SecurityEventRepository(session).list_for_session(session_id)
        decisions = DetectionDecisionRepository(session).list_for_session(session_id)

    decision_by_event = {
        decision.trigger_event_id: decision for decision in decisions
    }
    return SessionTimelineResponse(
        session_id=session_id,
        items=tuple(
            SessionTimelineItem(
                event=event,
                decision=decision_by_event.get(event.id),
            )
            for event in events
        ),
    )
