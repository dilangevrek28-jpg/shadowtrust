"""Minimal JSON logging for machine-readable ShadowTrust telemetry."""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from typing import TextIO

from shadowtrust.observability.request_context import current_request_id


class JsonFormatter(logging.Formatter):
    """Serialize one log record as a stable single-line JSON document."""

    def format(self, record: logging.LogRecord) -> str:
        timestamp = datetime.fromtimestamp(record.created, timezone.utc)
        payload: dict[str, object] = {
            "timestamp": timestamp.isoformat().replace("+00:00", "Z"),
            "level": record.levelname.lower(),
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": current_request_id.get(),
        }
        details = getattr(record, "structured_details", None)
        if details:
            payload["details"] = details
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            default=str,
        )


def configure_application_logging(
    level: str = "info",
    *,
    stream: TextIO | None = None,
) -> logging.Logger:
    """Configure only ShadowTrust loggers without changing library loggers."""

    handler = logging.StreamHandler(stream or sys.stdout)
    handler.setFormatter(JsonFormatter())

    package_logger = logging.getLogger("shadowtrust")
    package_logger.handlers.clear()
    package_logger.addHandler(handler)
    package_logger.setLevel(level.upper())
    package_logger.propagate = False
    return package_logger


def log_structured(
    logger: logging.Logger,
    level: int,
    message: str,
    **details: object,
) -> None:
    """Attach explicit structured details without interpolating free-form text."""

    logger.log(level, message, extra={"structured_details": details})
