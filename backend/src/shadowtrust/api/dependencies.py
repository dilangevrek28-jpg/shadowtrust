"""FastAPI dependencies that expose application resources."""

from typing import Annotated

from fastapi import HTTPException, Request, Response, Security, status
from fastapi.security import APIKeyHeader
from sqlalchemy.orm import Session, sessionmaker

from shadowtrust.api.access_control import (
    ApiKeyAccessController,
    InvalidApiKeyError,
    MissingApiKeyError,
    RateLimitExceededError,
)
from shadowtrust.application import ProcessSecurityEventService, ReplayDecisionService
from shadowtrust.observability import MetricsRegistry


event_api_key = APIKeyHeader(name="X-API-Key", auto_error=False)
analyst_api_key = APIKeyHeader(name="X-Analyst-API-Key", auto_error=False)
metrics_api_key = APIKeyHeader(name="X-Metrics-API-Key", auto_error=False)


def get_event_service(request: Request) -> ProcessSecurityEventService:
    return request.app.state.event_service


def get_session_factory(request: Request) -> sessionmaker[Session]:
    return request.app.state.session_factory


def get_metrics_registry(request: Request) -> MetricsRegistry:
    return request.app.state.metrics_registry


def get_replay_service(request: Request) -> ReplayDecisionService:
    return request.app.state.replay_service


def require_metrics_access(
    request: Request,
    api_key: Annotated[str | None, Security(metrics_api_key)],
) -> None:
    controller: ApiKeyAccessController = request.app.state.metrics_access_controller
    anonymous_identity = request.client.host if request.client else "unknown"
    try:
        controller.authorize(api_key, anonymous_identity=anonymous_identity)
    except MissingApiKeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "metrics_api_key_required", "message": "A valid metrics API key is required."},
            headers={"WWW-Authenticate": "ApiKey"},
        ) from exc
    except InvalidApiKeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "metrics_api_key_invalid", "message": "The metrics API key is invalid."},
        ) from exc
    except RateLimitExceededError as exc:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={"code": "rate_limit_exceeded", "message": "The metrics request limit was exceeded."},
            headers={"Retry-After": str(exc.retry_after_seconds)},
        ) from exc


def require_event_ingestion_access(
    request: Request,
    response: Response,
    api_key: Annotated[str | None, Security(event_api_key)],
) -> None:
    controller: ApiKeyAccessController = request.app.state.ingestion_access_controller
    anonymous_identity = request.client.host if request.client else "unknown"
    try:
        decision = controller.authorize(
            api_key,
            anonymous_identity=anonymous_identity,
        )
    except MissingApiKeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "code": "api_key_required",
                "message": "A valid event-ingestion API key is required.",
            },
            headers={"WWW-Authenticate": "ApiKey"},
        ) from exc
    except InvalidApiKeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "code": "api_key_invalid",
                "message": "The event-ingestion API key is invalid.",
            },
        ) from exc
    except RateLimitExceededError as exc:
        retry_after = str(exc.retry_after_seconds)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "code": "rate_limit_exceeded",
                "message": "The event-ingestion request limit was exceeded.",
            },
            headers={
                "Retry-After": retry_after,
                "X-RateLimit-Remaining": "0",
            },
        ) from exc

    response.headers["X-RateLimit-Limit"] = str(decision.limit)
    response.headers["X-RateLimit-Remaining"] = str(decision.remaining)


def require_analyst_access(
    request: Request,
    response: Response,
    api_key: Annotated[str | None, Security(analyst_api_key)],
) -> None:
    controller: ApiKeyAccessController = request.app.state.analyst_access_controller
    anonymous_identity = request.client.host if request.client else "unknown"
    try:
        decision = controller.authorize(
            api_key,
            anonymous_identity=anonymous_identity,
        )
    except MissingApiKeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "code": "analyst_api_key_required",
                "message": "A valid analyst API key is required.",
            },
            headers={"WWW-Authenticate": "ApiKey"},
        ) from exc
    except InvalidApiKeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "code": "analyst_api_key_invalid",
                "message": "The analyst API key is invalid.",
            },
        ) from exc
    except RateLimitExceededError as exc:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "code": "rate_limit_exceeded",
                "message": "The analyst request limit was exceeded.",
            },
            headers={
                "Retry-After": str(exc.retry_after_seconds),
                "X-RateLimit-Remaining": "0",
            },
        ) from exc

    response.headers["X-RateLimit-Limit"] = str(decision.limit)
    response.headers["X-RateLimit-Remaining"] = str(decision.remaining)
