"""HTTP boundary protections for request size and response headers."""

from __future__ import annotations

import logging
from collections.abc import Sequence

from fastapi.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send


SECURITY_HEADERS: tuple[tuple[bytes, bytes], ...] = (
    (b"cache-control", b"no-store"),
    (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"),
    (b"referrer-policy", b"no-referrer"),
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
)
logger = logging.getLogger("shadowtrust.api.security")


class ApiSecurityMiddleware:
    """Limit buffered request bodies and attach defensive response headers."""

    def __init__(self, app: ASGIApp, *, max_body_bytes: int) -> None:
        self._app = app
        self._max_body_bytes = max_body_bytes

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        response_started = False

        async def send_with_security_headers(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
                protected_names = {name for name, _value in SECURITY_HEADERS}
                headers = [
                    item
                    for item in message.get("headers", ())
                    if item[0].lower() not in protected_names
                ]
                headers.extend(SECURITY_HEADERS)
                message = {**message, "headers": headers}
            await send(message)

        if self._declared_body_is_too_large(scope.get("headers", ())):
            await self._send_too_large(
                scope,
                receive,
                send_with_security_headers,
            )
            return

        buffered_messages: list[Message] = []
        total_bytes = 0
        while True:
            message = await receive()
            buffered_messages.append(message)
            if message["type"] != "http.request":
                break
            total_bytes += len(message.get("body", b""))
            if total_bytes > self._max_body_bytes:
                await self._send_too_large(
                    scope,
                    receive,
                    send_with_security_headers,
                )
                return
            if not message.get("more_body", False):
                break

        message_index = 0

        async def replay_receive() -> Message:
            nonlocal message_index
            if message_index < len(buffered_messages):
                message = buffered_messages[message_index]
                message_index += 1
                return message
            return {"type": "http.disconnect"}

        try:
            await self._app(scope, replay_receive, send_with_security_headers)
        except Exception:
            if response_started:
                raise
            logger.exception("unhandled_application_error")
            response = JSONResponse(
                status_code=500,
                content={
                    "error": {
                        "code": "internal_server_error",
                        "message": "An unexpected server error occurred.",
                    }
                },
            )
            await response(scope, replay_receive, send_with_security_headers)

    def _declared_body_is_too_large(
        self,
        headers: Sequence[tuple[bytes, bytes]],
    ) -> bool:
        for name, value in headers:
            if name.lower() != b"content-length":
                continue
            try:
                return int(value) > self._max_body_bytes
            except ValueError:
                return False
        return False

    async def _send_too_large(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        response = JSONResponse(
            status_code=413,
            content={
                "error": {
                    "code": "request_body_too_large",
                    "message": "Request body exceeds the configured size limit.",
                }
            },
        )
        await response(scope, receive, send)
