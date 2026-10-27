from collections.abc import Iterator
from io import StringIO
import json

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
from shadowtrust.observability import configure_application_logging


ANALYST_KEY = "analyst-access-key-1234567890"


@pytest.fixture
def analyst_stack() -> Iterator[tuple[TestClient, object]]:
    database_engine = create_database_engine()
    create_schema(database_engine)
    session_factory = build_session_factory(database_engine)
    app = create_app(
        session_factory,
        analyst_api_keys=(ANALYST_KEY,),
    )
    with TestClient(app) as client:
        yield client, session_factory
    database_engine.dispose()


def scenario_named(name: str):
    return next(item for item in generate_scenarios() if item.name == name)


def ingest_scenario(client, session_factory, scenario) -> None:
    with transactional_session(session_factory) as session:
        UserBaselineRepository(session).add(scenario.baseline)
    for event in scenario.events:
        response = client.post(
            "/api/v1/events",
            json=event.model_dump(mode="json"),
        )
        assert response.status_code == 201


def analyst_headers() -> dict[str, str]:
    return {"X-Analyst-API-Key": ANALYST_KEY}


def analyst_mutation_headers() -> dict[str, str]:
    return {
        "X-Analyst-API-Key": ANALYST_KEY,
        "X-Analyst-ID": "analyst.one",
    }


def test_analyst_endpoint_requires_its_own_api_key(analyst_stack) -> None:
    client, _session_factory = analyst_stack

    missing = client.get("/api/v1/analyst/sessions")
    invalid = client.get(
        "/api/v1/analyst/sessions",
        headers={"X-Analyst-API-Key": "wrong-analyst-key-12345"},
    )

    assert missing.status_code == 401
    assert missing.json()["error"]["code"] == "analyst_api_key_required"
    assert invalid.status_code == 403
    assert invalid.json()["error"]["code"] == "analyst_api_key_invalid"


def test_risky_sessions_return_only_latest_decision_per_session(
    analyst_stack,
) -> None:
    client, session_factory = analyst_stack
    normal = scenario_named("normal_regular_login")
    attack = scenario_named("ato_recovery_device_transfer")
    ingest_scenario(client, session_factory, normal)
    ingest_scenario(client, session_factory, attack)

    response = client.get(
        "/api/v1/analyst/sessions",
        headers=analyst_headers(),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert len(body["items"]) == 1
    summary = body["items"][0]
    assert summary["session_id"] == str(attack.events[0].session_id)
    assert summary["risk_after"] == 100
    assert summary["risk_level"] == "critical"
    assert summary["trigger_event_type"] == "transfer_initiated"
    assert "RECOVERY_DEVICE_THEN_TRANSFER" in summary["matched_rules"]


def test_session_risk_filters_and_paginates(analyst_stack) -> None:
    client, session_factory = analyst_stack
    scenarios = (
        scenario_named("ato_recovery_device_transfer"),
        scenario_named("ato_credential_stuffing_transfer"),
        scenario_named("normal_regular_login"),
    )
    for scenario in scenarios:
        ingest_scenario(client, session_factory, scenario)

    first_page = client.get(
        "/api/v1/analyst/sessions",
        params={"minimum_risk": 0, "page": 1, "page_size": 1},
        headers=analyst_headers(),
    )
    second_page = client.get(
        "/api/v1/analyst/sessions",
        params={"minimum_risk": 0, "page": 2, "page_size": 1},
        headers=analyst_headers(),
    )
    critical = client.get(
        "/api/v1/analyst/sessions",
        params={"risk_level": "critical"},
        headers=analyst_headers(),
    )

    assert first_page.json()["total"] == 3
    assert len(first_page.json()["items"]) == 1
    assert len(second_page.json()["items"]) == 1
    assert first_page.json()["items"][0]["risk_after"] >= (
        second_page.json()["items"][0]["risk_after"]
    )
    assert all(
        item["risk_level"] == "critical"
        for item in critical.json()["items"]
    )


def test_analyst_can_read_complete_explainable_decision(analyst_stack) -> None:
    client, session_factory = analyst_stack
    scenario = scenario_named("ato_recovery_device_transfer")
    ingest_scenario(client, session_factory, scenario)
    summaries = client.get(
        "/api/v1/analyst/sessions",
        headers=analyst_headers(),
    ).json()
    decision_id = summaries["items"][0]["decision_id"]

    response = client.get(
        f"/api/v1/analyst/decisions/{decision_id}",
        headers=analyst_headers(),
    )

    assert response.status_code == 200
    decision = response.json()
    assert decision["id"] == decision_id
    assert decision["risk_after"] == 100
    assert decision["evaluations"]
    assert any(item["matched"] for item in decision["evaluations"])


def test_existing_event_reads_use_analyst_policy(analyst_stack) -> None:
    client, session_factory = analyst_stack
    scenario = scenario_named("normal_regular_login")
    ingest_scenario(client, session_factory, scenario)
    event_id = scenario.events[0].id

    missing = client.get(f"/api/v1/events/{event_id}")
    allowed = client.get(
        f"/api/v1/events/{event_id}",
        headers=analyst_headers(),
    )

    assert missing.status_code == 401
    assert allowed.status_code == 200


def test_analyst_opens_and_reads_an_audited_case(analyst_stack) -> None:
    client, session_factory = analyst_stack
    scenario = scenario_named("ato_recovery_device_transfer")
    ingest_scenario(client, session_factory, scenario)
    session_id = str(scenario.events[0].session_id)

    opened = client.post(
        "/api/v1/analyst/cases",
        json={"session_id": session_id, "note": "Customer callback required."},
        headers=analyst_mutation_headers(),
    )
    fetched = client.get(
        f"/api/v1/analyst/sessions/{session_id}/case",
        headers=analyst_headers(),
    )

    assert opened.status_code == 201
    assert fetched.status_code == 200
    case = fetched.json()
    assert case["status"] == "open"
    assert case["version"] == 1
    assert case["audit_trail"][0]["actor_id"] == "analyst.one"
    assert case["audit_trail"][0]["previous_status"] is None
    assert ANALYST_KEY not in fetched.text


def test_case_mutation_requires_identity_and_one_case_per_session(
    analyst_stack,
) -> None:
    client, session_factory = analyst_stack
    scenario = scenario_named("ato_recovery_device_transfer")
    ingest_scenario(client, session_factory, scenario)
    payload = {"session_id": str(scenario.events[0].session_id)}

    missing_identity = client.post(
        "/api/v1/analyst/cases",
        json=payload,
        headers=analyst_headers(),
    )
    first = client.post(
        "/api/v1/analyst/cases",
        json=payload,
        headers=analyst_mutation_headers(),
    )
    duplicate = client.post(
        "/api/v1/analyst/cases",
        json=payload,
        headers=analyst_mutation_headers(),
    )

    assert missing_identity.status_code == 422
    assert first.status_code == 201
    assert duplicate.status_code == 409
    assert duplicate.json()["error"]["code"] == "case_already_exists"


def test_case_transition_appends_audit_and_rejects_stale_version(
    analyst_stack,
) -> None:
    client, session_factory = analyst_stack
    scenario = scenario_named("ato_recovery_device_transfer")
    ingest_scenario(client, session_factory, scenario)
    opened = client.post(
        "/api/v1/analyst/cases",
        json={"session_id": str(scenario.events[0].session_id)},
        headers=analyst_mutation_headers(),
    ).json()
    endpoint = f"/api/v1/analyst/cases/{opened['id']}/transitions"
    payload = {
        "expected_version": 1,
        "status": "investigating",
        "note": "Transaction evidence is being reviewed.",
    }

    changed = client.post(
        endpoint,
        json=payload,
        headers=analyst_mutation_headers(),
    )
    stale = client.post(
        endpoint,
        json={**payload, "status": "confirmed_takeover"},
        headers=analyst_mutation_headers(),
    )

    assert changed.status_code == 200
    case = changed.json()
    assert case["status"] == "investigating"
    assert case["version"] == 2
    assert len(case["audit_trail"]) == 2
    assert case["audit_trail"][-1]["previous_status"] == "open"
    assert stale.status_code == 409
    assert stale.json()["error"]["code"] == "case_version_conflict"


def test_case_rejects_unknown_session_and_invalid_transition(
    analyst_stack,
) -> None:
    client, session_factory = analyst_stack
    unknown = client.post(
        "/api/v1/analyst/cases",
        json={"session_id": "00000000-0000-4000-8000-000000000999"},
        headers=analyst_mutation_headers(),
    )
    scenario = scenario_named("ato_recovery_device_transfer")
    ingest_scenario(client, session_factory, scenario)
    opened = client.post(
        "/api/v1/analyst/cases",
        json={"session_id": str(scenario.events[0].session_id)},
        headers=analyst_mutation_headers(),
    ).json()
    invalid = client.post(
        f"/api/v1/analyst/cases/{opened['id']}/transitions",
        json={
            "expected_version": 1,
            "status": "open",
            "note": "Status cannot remain unchanged.",
        },
        headers=analyst_mutation_headers(),
    )

    assert unknown.status_code == 404
    assert unknown.json()["error"]["code"] == "case_session_not_found"
    assert invalid.status_code == 409
    assert invalid.json()["error"]["code"] == "invalid_case_transition"


def test_session_queue_filters_and_counts_case_statuses(analyst_stack) -> None:
    client, session_factory = analyst_stack
    assigned = scenario_named("ato_recovery_device_transfer")
    unassigned = scenario_named("ato_credential_stuffing_transfer")
    ingest_scenario(client, session_factory, assigned)
    ingest_scenario(client, session_factory, unassigned)
    opened = client.post(
        "/api/v1/analyst/cases",
        json={"session_id": str(assigned.events[0].session_id)},
        headers=analyst_mutation_headers(),
    )
    assert opened.status_code == 201

    all_sessions = client.get(
        "/api/v1/analyst/sessions",
        params={"minimum_risk": 0},
        headers=analyst_headers(),
    ).json()
    open_only = client.get(
        "/api/v1/analyst/sessions",
        params={"minimum_risk": 0, "case_status": "open"},
        headers=analyst_headers(),
    ).json()
    unassigned_only = client.get(
        "/api/v1/analyst/sessions",
        params={"minimum_risk": 0, "case_status": "unassigned"},
        headers=analyst_headers(),
    ).json()

    assert all_sessions["case_counts"]["open"] == 1
    assert all_sessions["case_counts"]["unassigned"] == 1
    assigned_summary = next(
        item for item in all_sessions["items"] if item["case_status"] == "open"
    )
    assert assigned_summary["case_id"] == opened.json()["id"]
    assert assigned_summary["case_version"] == 1
    assert open_only["total"] == 1
    assert open_only["items"][0]["case_status"] == "open"
    assert unassigned_only["total"] == 1
    assert unassigned_only["items"][0]["case_status"] is None


def test_case_mutations_emit_structured_logs_without_secrets(analyst_stack) -> None:
    client, session_factory = analyst_stack
    scenario = scenario_named("ato_recovery_device_transfer")
    ingest_scenario(client, session_factory, scenario)
    stream = StringIO()
    package_logger = configure_application_logging("info", stream=stream)
    secret_note = "Sensitive customer callback context."
    try:
        opened = client.post(
            "/api/v1/analyst/cases",
            json={"session_id": str(scenario.events[0].session_id), "note": secret_note},
            headers=analyst_mutation_headers(),
        ).json()
        client.post(
            f"/api/v1/analyst/cases/{opened['id']}/transitions",
            json={
                "expected_version": 1,
                "status": "investigating",
                "note": "Review started.",
            },
            headers=analyst_mutation_headers(),
        )

        records = [json.loads(line) for line in stream.getvalue().splitlines()]
        messages = [record["message"] for record in records]
        assert "analyst_case_opened" in messages
        assert "analyst_case_transitioned" in messages
        serialized = stream.getvalue()
        assert ANALYST_KEY not in serialized
        assert secret_note not in serialized
        transition_log = next(
            item for item in records if item["message"] == "analyst_case_transitioned"
        )
        assert transition_log["details"]["actor_id"] == "analyst.one"
        assert transition_log["details"]["previous_status"] == "open"
        assert transition_log["details"]["new_status"] == "investigating"
    finally:
        package_logger.handlers.clear()
        package_logger.propagate = True
