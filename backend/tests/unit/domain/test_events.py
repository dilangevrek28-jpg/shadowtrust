from copy import deepcopy
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from uuid import UUID

import pytest
from pydantic import ValidationError

from shadowtrust.domain.events import (
    LoginSucceededEvent,
    TransferInitiatedEvent,
    parse_security_event,
)


EVENT_ID = "c71f1d6a-2d9a-4fd1-a1ad-ec03dfac25ee"
USER_ID = "232dd896-4bfa-4b90-86cf-11ce7c9bd742"
SESSION_ID = "d844f566-fbd9-432d-9e56-942909319293"
DEVICE_ID = "7bd829e0-0d04-496b-b621-9a08cb00b404"
CORRELATION_ID = "f2d3a104-18ac-4cf6-aec8-2033217910b8"


def valid_login_event() -> dict[str, object]:
    return {
        "id": EVENT_ID,
        "schema_version": "1.0",
        "event_type": "login_succeeded",
        "occurred_at": "2026-10-24T08:30:00+03:00",
        "received_at": "2026-10-24T08:30:01+03:00",
        "user_id": USER_ID,
        "session_id": SESSION_ID,
        "device_id": DEVICE_ID,
        "source_ip": "203.0.113.42",
        "geo_country": "tr",
        "correlation_id": CORRELATION_ID,
        "payload": {
            "authentication_method": "password_and_otp",
            "mfa_used": True,
        },
    }


def test_parses_valid_login_into_exact_event_type() -> None:
    event = parse_security_event(valid_login_event())

    assert isinstance(event, LoginSucceededEvent)
    assert event.geo_country == "TR"
    assert event.user_id == UUID(USER_ID)
    assert event.payload.mfa_used is True


def test_rejects_unknown_top_level_field() -> None:
    raw = valid_login_event()
    raw["risk_score"] = 99

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        parse_security_event(raw)


def test_rejects_ground_truth_label_to_prevent_detection_leakage() -> None:
    raw = valid_login_event()
    raw["label"] = "ato"

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        parse_security_event(raw)


def test_rejects_unknown_payload_field() -> None:
    raw = valid_login_event()
    payload = raw["payload"]
    assert isinstance(payload, dict)
    payload["device_is_trusted"] = True

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        parse_security_event(raw)


def test_rejects_naive_timestamp() -> None:
    raw = valid_login_event()
    raw["occurred_at"] = "2026-10-24T08:30:00"

    with pytest.raises(ValidationError, match="timezone offset"):
        parse_security_event(raw)


def test_allows_small_clock_skew() -> None:
    raw = valid_login_event()
    raw["occurred_at"] = "2026-10-24T08:34:59+03:00"

    assert parse_security_event(raw).occurred_at.minute == 34


def test_rejects_event_beyond_clock_skew_tolerance() -> None:
    raw = valid_login_event()
    raw["occurred_at"] = "2026-10-24T08:35:02+03:00"

    with pytest.raises(ValidationError, match="too far after received_at"):
        parse_security_event(raw)


def test_login_succeeded_requires_session_and_device_context() -> None:
    raw = valid_login_event()
    raw["session_id"] = None
    raw["device_id"] = None

    with pytest.raises(ValidationError, match="session_id, device_id"):
        parse_security_event(raw)


def test_event_type_selects_matching_payload_contract() -> None:
    raw = valid_login_event()
    raw["event_type"] = "transfer_initiated"

    with pytest.raises(ValidationError):
        parse_security_event(raw)


def test_rejects_unknown_event_type() -> None:
    raw = valid_login_event()
    raw["event_type"] = "admin_override"

    with pytest.raises(ValidationError, match="does not match any of the expected tags"):
        parse_security_event(raw)


def test_parses_valid_transfer_and_normalizes_currency() -> None:
    raw = valid_login_event()
    raw.update(
        {
            "event_type": "transfer_initiated",
            "payload": {
                "transaction_id": "d3837b8a-f3d7-4b2c-a224-63d7c260aa07",
                "beneficiary_id": "eb3f2e00-c3a5-4625-bcb6-137f6502ac87",
                "amount": "1250.50",
                "currency": "try",
            },
        }
    )

    event = parse_security_event(raw)

    assert isinstance(event, TransferInitiatedEvent)
    assert event.payload.amount == Decimal("1250.50")
    assert event.payload.currency == "TRY"


@pytest.mark.parametrize("amount", ["0", "-0.01", "12.345"])
def test_rejects_invalid_transfer_amount(amount: str) -> None:
    raw = valid_login_event()
    raw.update(
        {
            "event_type": "transfer_initiated",
            "payload": {
                "transaction_id": "d3837b8a-f3d7-4b2c-a224-63d7c260aa07",
                "beneficiary_id": "eb3f2e00-c3a5-4625-bcb6-137f6502ac87",
                "amount": amount,
                "currency": "TRY",
            },
        }
    )

    with pytest.raises(ValidationError):
        parse_security_event(raw)


def test_parsed_event_is_immutable() -> None:
    event = parse_security_event(valid_login_event())

    with pytest.raises(ValidationError, match="Instance is frozen"):
        event.geo_country = "US"  # type: ignore[misc]


def test_timestamp_objects_with_offsets_are_supported() -> None:
    raw = deepcopy(valid_login_event())
    received_at = datetime(2026, 10, 24, 8, 30, tzinfo=timezone(timedelta(hours=3)))
    raw["occurred_at"] = received_at
    raw["received_at"] = received_at

    assert parse_security_event(raw).received_at == received_at
