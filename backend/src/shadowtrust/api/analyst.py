"""Analyst investigation, replay, and case-management endpoints."""

import logging

from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from sqlalchemy.orm import Session, sessionmaker

from shadowtrust.api.dependencies import (
    get_session_factory,
    get_metrics_registry,
    get_replay_service,
    require_analyst_access,
)
from shadowtrust.api.schemas import (
    ErrorResponse,
    DecisionReplayResponse,
    OpenAnalystCaseRequest,
    PaginatedSessionRiskResponse,
    SessionRiskSummary,
    SessionCaseCounts,
    TransitionAnalystCaseRequest,
)
from shadowtrust.application import (
    CaseAlreadyExistsError,
    CaseManagementService,
    CaseNotFoundError,
    CaseSessionNotFoundError,
    CaseVersionConflictError,
    InvalidCaseTransitionError,
    DecisionReplayNotFoundError,
    DecisionReplayUnavailableError,
    ReplayDecisionService,
)
from shadowtrust.domain.cases import AnalystCase, CaseStatus
from shadowtrust.observability import MetricsRegistry
from shadowtrust.observability import log_structured
from shadowtrust.domain.decisions import DetectionDecision, RiskLevel
from shadowtrust.persistence import (
    DetectionDecisionRepository,
    transactional_session,
)


analyst_router = APIRouter(
    prefix="/api/v1/analyst",
    tags=["analyst"],
    dependencies=[Depends(require_analyst_access)],
)
logger = logging.getLogger("shadowtrust.api.analyst")

AnalystIdHeader = Annotated[
    str,
    Header(
        alias="X-Analyst-ID",
        min_length=3,
        max_length=64,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._@-]{2,63}$",
    ),
]


@analyst_router.get(
    "/sessions",
    response_model=PaginatedSessionRiskResponse,
)
def list_risky_sessions(
    session_factory: Annotated[
        sessionmaker[Session], Depends(get_session_factory)
    ],
    minimum_risk: Annotated[int, Query(ge=0, le=100)] = 1,
    risk_level: RiskLevel | None = None,
    case_status: CaseStatus | Literal["unassigned"] | None = None,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 25,
) -> PaginatedSessionRiskResponse:
    offset = (page - 1) * page_size
    with transactional_session(session_factory) as session:
        snapshots, total, case_counts = DetectionDecisionRepository(
            session
        ).search_latest_by_session(
            minimum_risk=minimum_risk,
            risk_level=risk_level,
            case_status=(case_status if isinstance(case_status, CaseStatus) else None),
            unassigned_only=case_status == "unassigned",
            offset=offset,
            limit=page_size,
        )

    return PaginatedSessionRiskResponse(
        page=page,
        page_size=page_size,
        total=total,
        case_counts=SessionCaseCounts(
            unassigned=case_counts.unassigned,
            open=case_counts.open,
            investigating=case_counts.investigating,
            confirmed_takeover=case_counts.confirmed_takeover,
            false_positive=case_counts.false_positive,
            closed=case_counts.closed,
        ),
        items=tuple(
            SessionRiskSummary(
                session_id=snapshot.decision.session_id,
                decision_id=snapshot.decision.id,
                trigger_event_id=snapshot.decision.trigger_event_id,
                trigger_event_type=snapshot.trigger_event.event_type,
                occurred_at=snapshot.trigger_event.occurred_at,
                risk_before=snapshot.decision.risk_before,
                risk_after=snapshot.decision.risk_after,
                risk_delta=snapshot.decision.risk_delta,
                risk_level=snapshot.decision.risk_level,
                recommended_actions=snapshot.decision.recommended_actions,
                explanation=snapshot.decision.explanation,
                matched_rules=tuple(
                    evaluation.rule_code
                    for evaluation in snapshot.decision.evaluations
                    if evaluation.matched
                ),
                case_id=snapshot.case_id,
                case_status=snapshot.case_status,
                case_version=snapshot.case_version,
            )
            for snapshot in snapshots
        ),
    )


@analyst_router.get(
    "/decisions/{decision_id}",
    response_model=DetectionDecision,
    responses={404: {"model": ErrorResponse}},
)
def get_decision(
    decision_id: UUID,
    session_factory: Annotated[
        sessionmaker[Session], Depends(get_session_factory)
    ],
) -> DetectionDecision:
    with transactional_session(session_factory) as session:
        decision = DetectionDecisionRepository(session).get(decision_id)
    if decision is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "code": "decision_not_found",
                "message": "Detection decision not found.",
            },
        )
    return decision


@analyst_router.post(
    "/decisions/{decision_id}/replay",
    response_model=DecisionReplayResponse,
    responses={404: {"model": ErrorResponse}, 409: {"model": ErrorResponse}},
)
def replay_decision(
    decision_id: UUID,
    service: Annotated[ReplayDecisionService, Depends(get_replay_service)],
    metrics: Annotated[MetricsRegistry, Depends(get_metrics_registry)],
) -> DecisionReplayResponse:
    try:
        result = service.replay(decision_id)
    except DecisionReplayNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "decision_not_found", "message": str(exc)},
        ) from exc
    except DecisionReplayUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "decision_replay_unavailable", "message": str(exc)},
        ) from exc

    metrics.increment(
        "shadowtrust_decision_replays_total",
        status=result.status.value,
    )
    log_structured(
        logger,
        logging.INFO,
        "decision_replayed",
        decision_id=str(decision_id),
        replay_status=result.status.value,
        differences=list(result.differences),
    )
    return DecisionReplayResponse(
        status=result.status.value,
        original_decision=result.original_decision,
        replayed_decision=result.replayed_decision,
        differences=result.differences,
    )


@analyst_router.post(
    "/cases",
    response_model=AnalystCase,
    status_code=status.HTTP_201_CREATED,
    responses={404: {"model": ErrorResponse}, 409: {"model": ErrorResponse}},
)
def open_case(
    request: OpenAnalystCaseRequest,
    analyst_id: AnalystIdHeader,
    session_factory: Annotated[
        sessionmaker[Session], Depends(get_session_factory)
    ],
    metrics: Annotated[MetricsRegistry, Depends(get_metrics_registry)],
) -> AnalystCase:
    service = CaseManagementService(session_factory)
    try:
        case = service.open_case(
            session_id=request.session_id,
            actor_id=analyst_id,
            note=request.note,
        )
        metrics.increment("shadowtrust_cases_opened_total")
        return case
    except CaseSessionNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "case_session_not_found", "message": str(exc)},
        ) from exc
    except CaseAlreadyExistsError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "case_already_exists", "message": str(exc)},
        ) from exc


@analyst_router.get(
    "/cases/{case_id}",
    response_model=AnalystCase,
    responses={404: {"model": ErrorResponse}},
)
def get_case(
    case_id: UUID,
    session_factory: Annotated[
        sessionmaker[Session], Depends(get_session_factory)
    ],
) -> AnalystCase:
    try:
        return CaseManagementService(session_factory).get_case(case_id)
    except CaseNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "case_not_found", "message": str(exc)},
        ) from exc


@analyst_router.get(
    "/sessions/{session_id}/case",
    response_model=AnalystCase,
    responses={404: {"model": ErrorResponse}},
)
def get_case_for_session(
    session_id: UUID,
    session_factory: Annotated[
        sessionmaker[Session], Depends(get_session_factory)
    ],
) -> AnalystCase:
    try:
        return CaseManagementService(session_factory).get_case_for_session(
            session_id
        )
    except CaseNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "case_not_found", "message": str(exc)},
        ) from exc


@analyst_router.post(
    "/cases/{case_id}/transitions",
    response_model=AnalystCase,
    responses={404: {"model": ErrorResponse}, 409: {"model": ErrorResponse}},
)
def transition_case_status(
    case_id: UUID,
    request: TransitionAnalystCaseRequest,
    analyst_id: AnalystIdHeader,
    session_factory: Annotated[
        sessionmaker[Session], Depends(get_session_factory)
    ],
    metrics: Annotated[MetricsRegistry, Depends(get_metrics_registry)],
) -> AnalystCase:
    service = CaseManagementService(session_factory)
    try:
        case = service.transition(
            case_id=case_id,
            expected_version=request.expected_version,
            new_status=request.status,
            actor_id=analyst_id,
            note=request.note,
        )
        previous_status = case.audit_trail[-1].previous_status
        if previous_status is None:
            raise RuntimeError("a case transition must record its previous status")
        metrics.increment(
            "shadowtrust_case_transitions_total",
            previous_status=previous_status.value,
            new_status=case.status.value,
        )
        return case
    except CaseNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "case_not_found", "message": str(exc)},
        ) from exc
    except CaseVersionConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "case_version_conflict", "message": str(exc)},
        ) from exc
    except InvalidCaseTransitionError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "invalid_case_transition", "message": str(exc)},
        ) from exc
