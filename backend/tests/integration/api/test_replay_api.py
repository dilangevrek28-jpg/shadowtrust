from collections.abc import Iterator
from dataclasses import replace
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from shadowtrust.api import create_app
from shadowtrust.application import ReplayDecisionService
from shadowtrust.detection import build_default_detection_engine
from shadowtrust.detection.context import DetectionContext
from shadowtrust.domain.decisions import RuleEvaluation
from shadowtrust.persistence import (
    UserBaselineRepository,
    build_session_factory,
    create_database_engine,
    create_schema,
    transactional_session,
)
from shadowtrust.persistence.models import DetectionDecisionRecord
from shadowtrust.synthetic import generate_scenarios


ANALYST_KEY = "analyst-access-key-1234567890"


@pytest.fixture
def replay_stack() -> Iterator[tuple[TestClient, object, object]]:
    database_engine = create_database_engine()
    create_schema(database_engine)
    session_factory = build_session_factory(database_engine)
    app = create_app(session_factory, analyst_api_keys=(ANALYST_KEY,))
    with TestClient(app) as client:
        yield client, session_factory, app
    database_engine.dispose()


def ingest_attack(client: TestClient, session_factory) -> str:
    scenario = next(
        item
        for item in generate_scenarios()
        if item.name == "ato_recovery_device_transfer"
    )
    with transactional_session(session_factory) as session:
        UserBaselineRepository(session).add(scenario.baseline)
    decision_id = ""
    for event in scenario.events:
        response = client.post("/api/v1/events", json=event.model_dump(mode="json"))
        assert response.status_code == 201
        decision_id = response.json()["decision"]["id"]
    return decision_id


def replay(client: TestClient, decision_id: str):
    return client.post(
        f"/api/v1/analyst/decisions/{decision_id}/replay",
        headers={"X-Analyst-API-Key": ANALYST_KEY},
    )


def test_replay_reproduces_decision_without_persisting_a_duplicate(
    replay_stack,
) -> None:
    client, session_factory, _app = replay_stack
    decision_id = ingest_attack(client, session_factory)
    with transactional_session(session_factory) as session:
        count_before = session.scalar(
            select(func.count()).select_from(DetectionDecisionRecord)
        )

    response = replay(client, decision_id)

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "reproduced"
    assert body["differences"] == []
    assert body["original_decision"]["id"] == decision_id
    assert body["replayed_decision"]["id"] != decision_id
    assert body["replayed_decision"]["risk_after"] == body["original_decision"]["risk_after"]
    with transactional_session(session_factory) as session:
        count_after = session.scalar(
            select(func.count()).select_from(DetectionDecisionRecord)
        )
    assert count_after == count_before
    assert 'shadowtrust_decision_replays_total{status="reproduced"} 1' in client.get(
        "/metrics"
    ).text


def test_replay_reports_incompatible_engine_version(replay_stack) -> None:
    client, session_factory, app = replay_stack
    decision_id = ingest_attack(client, session_factory)
    incompatible_engine = replace(
        build_default_detection_engine(),
        engine_version="incompatible-test-engine",
    )
    app.state.replay_service = ReplayDecisionService(
        session_factory,
        incompatible_engine,
    )

    response = replay(client, decision_id)

    assert response.status_code == 200
    assert response.json()["status"] == "incompatible"
    assert response.json()["replayed_decision"] is None
    assert response.json()["differences"] == ["engine_version"]


def test_replay_detects_unversioned_rule_behavior_drift(replay_stack) -> None:
    client, session_factory, app = replay_stack
    decision_id = ingest_attack(client, session_factory)
    engine = build_default_detection_engine()

    class ReasonDriftRule:
        code = engine.rules[0].code
        version = engine.rules[0].version

        def evaluate(self, context: DetectionContext) -> RuleEvaluation:
            evaluation = engine.rules[0].evaluate(context)
            return evaluation.model_copy(
                update={"reason": f"{evaluation.reason} Behavior changed."}
            )

    drifted_engine = replace(
        engine,
        rules=(ReasonDriftRule(), *engine.rules[1:]),
    )
    app.state.replay_service = ReplayDecisionService(session_factory, drifted_engine)

    response = replay(client, decision_id)

    assert response.status_code == 200
    assert response.json()["status"] == "drifted"
    assert "evaluations" in response.json()["differences"]
    assert response.json()["replayed_decision"] is not None


def test_replay_returns_structured_404_for_unknown_decision(replay_stack) -> None:
    client, _session_factory, _app = replay_stack

    response = replay(client, str(uuid4()))

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "decision_not_found"
