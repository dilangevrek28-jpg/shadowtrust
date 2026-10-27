"""Pure ASGI middleware for request correlation and access telemetry."""

from __future__ import annotations

import logging
from time import perf_counter
from uuid import UUID, uuid4

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from shadowtrust.observability.logging import log_structured
from shadowtrust.observability.request_context import request_id_context


logger = logging.getLogger("shadowtrust.http")
REQUEST_ID_HEADER = b"x-request-id"


def _request_id_from_scope(scope: Scope) -> str:
    for name, raw_value in scope.get("headers", ()):
        if name.lower() != REQUEST_ID_HEADER:
            continue
        try:
            return str(UUID(raw_value.decode("ascii")))
        except (UnicodeDecodeError, ValueError):
            break
    return str(uuid4())


class RequestContextMiddleware:
    """Correlate every HTTP request and emit privacy-conscious access logs."""

    def __init__(self, app: ASGIApp) -> None:
        self._app = app

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        request_id = _request_id_from_scope(scope)
        method = scope["method"]
        path = scope["path"]
        started_at = perf_counter()
        status_code = 500

        async def send_with_request_id(message: Message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
                headers = [
                    item
                    for item in message.get("headers", ())
                    if item[0].lower() != REQUEST_ID_HEADER
                ]
                headers.append((REQUEST_ID_HEADER, request_id.encode("ascii")))
                message = {**message, "headers": headers}
            await send(message)

        with request_id_context(request_id):
            log_structured(
                logger,
                logging.INFO,
                "request_started",
                method=method,
                path=path,
            )
            try:
                await self._app(scope, receive, send_with_request_id)
            except Exception:
                logger.exception(
                    "request_failed",
                    extra={
                        "structured_details": {
                            "method": method,
                            "path": path,
                            "duration_ms": round(
                                (perf_counter() - started_at) * 1000,
                                3,
                            ),
                        }
                    },
                )
                raise
            else:
                log_structured(
                    logger,
                    logging.INFO,
                    "request_completed",
                    method=method,
                    path=path,
                    status_code=status_code,
                    duration_ms=round((perf_counter() - started_at) * 1000, 3),
                )
