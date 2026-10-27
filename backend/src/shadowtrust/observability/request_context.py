"""Request correlation context shared by middleware and JSON logging."""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from collections.abc import Iterator


current_request_id: ContextVar[str | None] = ContextVar(
    "shadowtrust_request_id",
    default=None,
)


@contextmanager
def request_id_context(request_id: str) -> Iterator[None]:
    """Bind a request ID to the current async/thread context and then restore it."""

    token = current_request_id.set(request_id)
    try:
        yield
    finally:
        current_request_id.reset(token)
