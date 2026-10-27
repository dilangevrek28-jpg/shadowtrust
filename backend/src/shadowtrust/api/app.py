"""FastAPI application factory for dependency-injected ShadowTrust APIs."""

from __future__ import annotations

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session, sessionmaker
from starlette.types import Lifespan

from shadowtrust.api.access_control import ApiKeyAccessController
from shadowtrust.api.analyst import analyst_router
from shadowtrust.api.health import health_router
from shadowtrust.api.metrics import metrics_router
from shadowtrust.api.routes import router
from shadowtrust.api.security import ApiSecurityMiddleware
from shadowtrust.application import (
    EventConflictError,
    OutOfOrderEventError,
    ProcessSecurityEventService,
    ReplayDecisionService,
)
from shadowtrust.detection import build_default_detection_engine
from shadowtrust.detection.engine import DetectionEngine
from shadowtrust.observability import RequestContextMiddleware
from shadowtrust.observability import MetricsRegistry


def _error_response(
    status_code: int,
    code: str,
    message: str,
    *,
    issues: list[dict[str, object]] | None = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    error: dict[str, object] = {"code": code, "message": message}
    if issues is not None:
        error["issues"] = issues
    return JSONResponse(
        status_code=status_code,
        content={"error": error},
        headers=headers,
    )


def create_app(
    session_factory: sessionmaker[Session],
    *,
    detection_engine: DetectionEngine | None = None,
    lifespan: Lifespan[FastAPI] | None = None,
    max_request_body_bytes: int = 1_048_576,
    ingestion_api_keys: tuple[str, ...] = (),
    analyst_api_keys: tuple[str, ...] = (),
    metrics_api_keys: tuple[str, ...] = (),
    rate_limit_requests: int = 120,
    rate_limit_window_seconds: int = 60,
) -> FastAPI:
    """Build an API without creating a database or schema as an import side effect."""

    app = FastAPI(
        title="ShadowTrust API",
        version="0.1.0",
        description="Explainable account-takeover detection API.",
        lifespan=lifespan,
    )
    app.add_middleware(
        ApiSecurityMiddleware,
        max_body_bytes=max_request_body_bytes,
    )
    app.add_middleware(RequestContextMiddleware)
    engine = detection_engine or build_default_detection_engine()
    app.state.session_factory = session_factory
    app.state.event_service = ProcessSecurityEventService(session_factory, engine)
    app.state.replay_service = ReplayDecisionService(session_factory, engine)
    app.state.ingestion_access_controller = ApiKeyAccessController(
        ingestion_api_keys,
        request_limit=rate_limit_requests,
        window_seconds=rate_limit_window_seconds,
    )
    app.state.analyst_access_controller = ApiKeyAccessController(
        analyst_api_keys,
        request_limit=rate_limit_requests,
        window_seconds=rate_limit_window_seconds,
    )
    app.state.metrics_access_controller = ApiKeyAccessController(
        metrics_api_keys,
        request_limit=rate_limit_requests,
        window_seconds=rate_limit_window_seconds,
    )
    app.state.metrics_registry = MetricsRegistry()

    @app.exception_handler(EventConflictError)
    async def handle_event_conflict(
        _request: Request, exc: EventConflictError
    ) -> JSONResponse:
        return _error_response(
            status.HTTP_409_CONFLICT,
            "event_conflict",
            str(exc),
        )

    @app.exception_handler(OutOfOrderEventError)
    async def handle_out_of_order_event(
        _request: Request, exc: OutOfOrderEventError
    ) -> JSONResponse:
        return _error_response(
            status.HTTP_409_CONFLICT,
            "out_of_order_event",
            str(exc),
        )

    @app.exception_handler(HTTPException)
    async def handle_http_exception(
        _request: Request, exc: HTTPException
    ) -> JSONResponse:
        detail = exc.detail
        if isinstance(detail, dict) and {"code", "message"} <= detail.keys():
            return _error_response(
                exc.status_code,
                detail["code"],
                detail["message"],
                headers=exc.headers,
            )
        return _error_response(
            exc.status_code,
            "http_error",
            str(detail),
            headers=exc.headers,
        )

    @app.exception_handler(RequestValidationError)
    async def handle_request_validation(
        _request: Request,
        exc: RequestValidationError,
    ) -> JSONResponse:
        issues = [
            {
                "location": list(error["loc"]),
                "message": error["msg"],
                "type": error["type"],
            }
            for error in exc.errors()
        ]
        return _error_response(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "request_validation_failed",
            "Request validation failed.",
            issues=issues,
        )

    app.include_router(health_router)
    app.include_router(metrics_router)
    app.include_router(analyst_router)
    app.include_router(router)
    return app
