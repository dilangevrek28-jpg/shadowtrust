"""Operational health endpoints for process and database monitoring."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from shadowtrust.api.dependencies import get_session_factory
from shadowtrust.api.schemas import ErrorResponse, HealthResponse
from shadowtrust.persistence import transactional_session
from shadowtrust.persistence.models import SecurityEventRecord


health_router = APIRouter(prefix="/health", tags=["health"])


@health_router.get("/live", response_model=HealthResponse)
def liveness() -> HealthResponse:
    """Report whether the API process can receive and execute requests."""

    return HealthResponse()


@health_router.get(
    "/ready",
    response_model=HealthResponse,
    responses={503: {"model": ErrorResponse}},
)
def readiness(
    session_factory: Annotated[
        sessionmaker[Session], Depends(get_session_factory)
    ],
) -> HealthResponse:
    """Verify both database connectivity and the expected migrated schema."""

    try:
        with transactional_session(session_factory) as session:
            session.execute(select(SecurityEventRecord.id).limit(1))
    except SQLAlchemyError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "code": "database_not_ready",
                "message": "Database connection or schema is not ready.",
            },
        ) from exc
    return HealthResponse()
