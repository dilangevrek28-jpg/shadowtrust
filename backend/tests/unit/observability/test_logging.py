import json
import logging
from io import StringIO

from shadowtrust.observability import (
    configure_application_logging,
    log_structured,
    request_id_context,
)


def test_json_logging_includes_request_context_and_structured_details() -> None:
    stream = StringIO()
    package_logger = configure_application_logging("info", stream=stream)

    try:
        with request_id_context("8efc86d8-31ac-48ef-b3ad-f1aa3d8c85db"):
            log_structured(
                logging.getLogger("shadowtrust.test"),
                logging.INFO,
                "example_completed",
                event_id="event-123",
                risk_after=70,
            )

        record = json.loads(stream.getvalue())
        assert record["timestamp"].endswith("Z")
        assert record["level"] == "info"
        assert record["logger"] == "shadowtrust.test"
        assert record["message"] == "example_completed"
        assert record["request_id"] == "8efc86d8-31ac-48ef-b3ad-f1aa3d8c85db"
        assert record["details"] == {"event_id": "event-123", "risk_after": 70}
    finally:
        package_logger.handlers.clear()
        package_logger.propagate = True


def test_request_context_is_restored_after_the_bound_scope() -> None:
    stream = StringIO()
    package_logger = configure_application_logging("info", stream=stream)

    try:
        with request_id_context("c7b35d37-e865-4df3-a5c1-d9333768bd06"):
            log_structured(
                logging.getLogger("shadowtrust.test"),
                logging.INFO,
                "inside_request",
            )
        log_structured(
            logging.getLogger("shadowtrust.test"),
            logging.INFO,
            "outside_request",
        )

        records = [json.loads(line) for line in stream.getvalue().splitlines()]
        assert records[0]["request_id"] == "c7b35d37-e865-4df3-a5c1-d9333768bd06"
        assert records[1]["request_id"] is None
    finally:
        package_logger.handlers.clear()
        package_logger.propagate = True
