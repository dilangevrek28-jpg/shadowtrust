from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from shadowtrust.api import create_app
from shadowtrust.persistence import (
    UserBaselineRepository,
    build_session_factory,
    create_database_engine,
    create_schema,
    transactional_session,
)
from shadowtrust.synthetic import generate_scenarios


INGESTION_KEY = "ingestion-access-key-1234567890"
ANALYST_KEY = "analyst-access-key-1234567890"
METRICS_KEY = "metrics-access-key-1234567890"


@pytest.fixture
def metrics_stack() -> Iterator[tuple[TestClient, object]]:
    database_engine = create_database_engine()
    create_schema(database_engine)
    session_factory = build_session_factory(database_engine)
    app = create_app(
        session_factory,
        ingestion_api_keys=(INGESTION_KEY,),
        analyst_api_keys=(ANALYST_KEY,),
        metrics_api_keys=(METRICS_KEY,),
    )
    with TestClient(app) as client:
        yield client, session_factory
    database_engine.dispose()


def scenario_named(name: str):
    return next(item for item in generate_scenarios() if item.name == name)


def metrics_headers() -> dict[str, str]:
    return {"X-Metrics-API-Key": METRICS_KEY}


def test_metrics_endpoint_requires_its_separate_api_key(metrics_stack) -> None:
    client, _session_factory = metrics_stack

    missing = client.get("/metrics")
    wrong_role = client.get(
        "/metrics",
        headers={"X-Metrics-API-Key": ANALYST_KEY},
    )
    allowed = client.get("/metrics", headers=metrics_headers())

    assert missing.status_code == 401
    assert missing.json()["error"]["code"] == "metrics_api_key_required"
    assert wrong_role.status_code == 403
    assert wrong_role.json()["error"]["code"] == "metrics_api_key_invalid"
    assert allowed.status_code == 200
    assert allowed.headers["content-type"].startswith("text/plain; version=0.0.4")


def test_event_metrics_distinguish_created_from_replayed(metrics_stack) -> None:
    client, session_factory = metrics_stack
    scenario = scenario_named("normal_regular_login")
    with transactional_session(session_factory) as session:
        UserBaselineRepository(session).add(scenario.baseline)
    payload = scenario.events[0].model_dump(mode="json")
    ingestion_headers = {"X-API-Key": INGESTION_KEY}

    assert client.post("/api/v1/events", json=payload, headers=ingestion_headers).status_code == 201
    assert client.post("/api/v1/events", json=payload, headers=ingestion_headers).status_code == 200
    output = client.get("/metrics", headers=metrics_headers()).text

    assert 'shadowtrust_events_processed_total{outcome="created"} 1' in output
    assert 'shadowtrust_events_processed_total{outcome="replayed"} 1' in output
    assert 'shadowtrust_decisions_total{risk_level="low"} 1' in output


def test_case_metrics_count_successful_mutations_only(metrics_stack) -> None:
    client, session_factory = metrics_stack
    scenario = scenario_named("ato_recovery_device_transfer")
    with transactional_session(session_factory) as session:
        UserBaselineRepository(session).add(scenario.baseline)
    ingestion_headers = {"X-API-Key": INGESTION_KEY}
    for event in scenario.events:
        response = client.post(
            "/api/v1/events",
            json=event.model_dump(mode="json"),
            headers=ingestion_headers,
        )
        assert response.status_code == 201

    analyst_headers = {
        "X-Analyst-API-Key": ANALYST_KEY,
        "X-Analyst-ID": "analyst.one",
    }
    opened = client.post(
        "/api/v1/analyst/cases",
        json={"session_id": str(scenario.events[0].session_id), "note": "Initial review"},
        headers=analyst_headers,
    )
    assert opened.status_code == 201
    case_id = opened.json()["id"]
    transitioned = client.post(
        f"/api/v1/analyst/cases/{case_id}/transitions",
        json={"expected_version": 1, "status": "investigating", "note": "Started review"},
        headers=analyst_headers,
    )
    assert transitioned.status_code == 200

    output = client.get("/metrics", headers=metrics_headers()).text
    assert "shadowtrust_cases_opened_total 1" in output
    assert (
        'shadowtrust_case_transitions_total{new_status="investigating",'
        'previous_status="open"} 1'
        in output
    )
