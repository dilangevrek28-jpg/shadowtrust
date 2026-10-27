from collections.abc import Iterator
from io import StringIO
import json
import logging
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from shadowtrust.api import create_app
from shadowtrust.observability import configure_application_logging
from shadowtrust.persistence import (
    UserBaselineRepository,
    build_session_factory,
    create_database_engine,
    create_schema,
    transactional_session,
)
from shadowtrust.persistence.models import SecurityEventRecord
from shadowtrust.synthetic import generate_scenarios


@pytest.fixture
def api_stack() -> Iterator[tuple[TestClient, object, object]]:
    database_engine = create_database_engine()
    create_schema(database_engine)
    session_factory = build_session_factory(database_engine)
    with TestClient(create_app(session_factory)) as client:
        yield client, session_factory, database_engine
    database_engine.dispose()


def scenario_named(name: str):
    return next(item for item in generate_scenarios() if item.name == name)


def seed_baseline(session_factory, scenario) -> None:
    with transactional_session(session_factory) as session:
        UserBaselineRepository(session).add(scenario.baseline)


def test_post_event_creates_decision_and_retry_is_idempotent(api_stack) -> None:
    client, session_factory, _database_engine = api_stack
    scenario = scenario_named("normal_regular_login")
    seed_baseline(session_factory, scenario)
    event = scenario.events[0]
    payload = event.model_dump(mode="json")

    created = client.post("/api/v1/events", json=payload)
    retried = client.post("/api/v1/events", json=payload)

    assert created.status_code == 201
    assert created.json()["created"] is True
    assert created.json()["event"]["id"] == str(event.id)
    assert created.json()["decision"]["trigger_event_id"] == str(event.id)
    assert retried.status_code == 200
    assert retried.json()["created"] is False
    assert retried.json()["decision"]["id"] == created.json()["decision"]["id"]

    with transactional_session(session_factory) as session:
        count = session.scalar(select(func.count()).select_from(SecurityEventRecord))
    assert count == 1


def test_post_event_rejects_invalid_contract_without_persisting(api_stack) -> None:
    client, session_factory, _database_engine = api_stack
    event = scenario_named("normal_regular_login").events[0]
    payload = event.model_dump(mode="json")
    payload["unexpected_field"] = "must be rejected"

    response = client.post("/api/v1/events", json=payload)

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "request_validation_failed"
    with transactional_session(session_factory) as session:
        count = session.scalar(select(func.count()).select_from(SecurityEventRecord))
    assert count == 0


def test_post_event_maps_identity_conflict_to_409(api_stack) -> None:
    client, _session_factory, _database_engine = api_stack
    event = scenario_named("normal_regular_login").events[0]
    original = event.model_dump(mode="json")
    altered = {**original, "geo_country": "US"}

    assert client.post("/api/v1/events", json=original).status_code == 201
    response = client.post("/api/v1/events", json=altered)

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "event_conflict"


def test_post_event_maps_out_of_order_timeline_to_409(api_stack) -> None:
    client, session_factory, _database_engine = api_stack
    scenario = scenario_named("ato_recovery_device_transfer")
    seed_baseline(session_factory, scenario)

    later_response = client.post(
        "/api/v1/events", json=scenario.events[1].model_dump(mode="json")
    )
    earlier_response = client.post(
        "/api/v1/events", json=scenario.events[0].model_dump(mode="json")
    )

    assert later_response.status_code == 201
    assert earlier_response.status_code == 409
    assert earlier_response.json()["error"]["code"] == "out_of_order_event"


def test_get_event_returns_event_and_structured_404(api_stack) -> None:
    client, _session_factory, _database_engine = api_stack
    event = scenario_named("normal_regular_login").events[0]
    client.post("/api/v1/events", json=event.model_dump(mode="json"))

    found = client.get(f"/api/v1/events/{event.id}")
    missing = client.get(f"/api/v1/events/{uuid4()}")

    assert found.status_code == 200
    assert found.json()["id"] == str(event.id)
    assert missing.status_code == 404
    assert missing.json() == {
        "error": {
            "code": "event_not_found",
            "message": "Security event not found.",
        }
    }


def test_session_timeline_orders_events_and_attaches_decisions(api_stack) -> None:
    client, session_factory, _database_engine = api_stack
    scenario = scenario_named("normal_travel_with_mfa")
    seed_baseline(session_factory, scenario)
    for event in scenario.events:
        response = client.post("/api/v1/events", json=event.model_dump(mode="json"))
        assert response.status_code == 201

    response = client.get(
        f"/api/v1/sessions/{scenario.events[0].session_id}/timeline"
    )

    assert response.status_code == 200
    body = response.json()
    assert body["session_id"] == str(scenario.events[0].session_id)
    assert [item["event"]["id"] for item in body["items"]] == [
        str(event.id) for event in scenario.events
    ]
    assert [item["decision"]["trigger_event_id"] for item in body["items"]] == [
        str(event.id) for event in scenario.events
    ]


def test_unknown_session_returns_an_empty_timeline(api_stack) -> None:
    client, _session_factory, _database_engine = api_stack
    unknown_session_id = uuid4()

    response = client.get(f"/api/v1/sessions/{unknown_session_id}/timeline")

    assert response.status_code == 200
    assert response.json() == {
        "session_id": str(unknown_session_id),
        "items": [],
    }


def test_event_log_is_correlated_and_excludes_raw_sensitive_payload(api_stack) -> None:
    client, _session_factory, _database_engine = api_stack
    event = scenario_named("normal_regular_login").events[0]
    stream = StringIO()
    package_logger = configure_application_logging("info", stream=stream)

    try:
        response = client.post(
            "/api/v1/events",
            json=event.model_dump(mode="json"),
        )
        records = [json.loads(line) for line in stream.getvalue().splitlines()]
        event_record = next(
            record
            for record in records
            if record["message"] == "security_event_processed"
        )

        assert event_record["request_id"] == response.headers["X-Request-ID"]
        assert event_record["details"]["event_id"] == str(event.id)
        assert event_record["details"]["event_type"] == event.event_type
        assert event_record["details"]["risk_after"] == 0
        serialized_record = json.dumps(event_record)
        assert "payload" not in serialized_record
        assert "source_ip" not in serialized_record
        assert "amount" not in serialized_record
    finally:
        package_logger.handlers.clear()
        package_logger.propagate = True
