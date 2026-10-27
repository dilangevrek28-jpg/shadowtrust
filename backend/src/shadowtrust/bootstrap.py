"""Composition root that wires runtime configuration to infrastructure."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

from shadowtrust.api import create_app
from shadowtrust.observability import configure_application_logging
from shadowtrust.persistence import build_session_factory, create_database_engine
from shadowtrust.settings import RuntimeSettings


def build_application(settings: RuntimeSettings | None = None) -> FastAPI:
    """Construct the complete process without creating or migrating tables."""

    runtime_settings = settings or RuntimeSettings.from_environment()
    configure_application_logging(runtime_settings.log_level)
    database_engine = create_database_engine(
        runtime_settings.database_url,
        echo=runtime_settings.database_echo,
    )
    session_factory = build_session_factory(database_engine)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        try:
            yield
        finally:
            database_engine.dispose()

    app = create_app(
        session_factory,
        lifespan=lifespan,
        max_request_body_bytes=runtime_settings.max_request_body_bytes,
        ingestion_api_keys=tuple(
            key.get_secret_value() for key in runtime_settings.ingestion_api_keys
        ),
        analyst_api_keys=tuple(
            key.get_secret_value() for key in runtime_settings.analyst_api_keys
        ),
        metrics_api_keys=tuple(
            key.get_secret_value() for key in runtime_settings.metrics_api_keys
        ),
        rate_limit_requests=runtime_settings.rate_limit_requests,
        rate_limit_window_seconds=runtime_settings.rate_limit_window_seconds,
    )
    app.state.settings = runtime_settings
    app.state.database_engine = database_engine
    return app
