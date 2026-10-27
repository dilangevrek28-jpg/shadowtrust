from fastapi.testclient import TestClient

from shadowtrust.api import create_app
from shadowtrust.persistence import (
    build_session_factory,
    create_database_engine,
    create_schema,
)
from shadowtrust.synthetic import generate_scenarios


API_KEY = "synthetic-producer-key-1234567890"


def protected_client(*, request_limit: int = 120):
    database_engine = create_database_engine()
    create_schema(database_engine)
    app = create_app(
        build_session_factory(database_engine),
        ingestion_api_keys=(API_KEY,),
        rate_limit_requests=request_limit,
        rate_limit_window_seconds=60,
    )
    return database_engine, TestClient(app)


def event_payload():
    return generate_scenarios()[0].events[0].model_dump(mode="json")


def test_missing_api_key_returns_401_with_authentication_challenge() -> None:
    database_engine, client = protected_client()

    with client:
        response = client.post("/api/v1/events", json=event_payload())

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "ApiKey"
    assert response.json()["error"]["code"] == "api_key_required"
    database_engine.dispose()


def test_invalid_api_key_returns_403_without_echoing_the_key() -> None:
    database_engine, client = protected_client()
    invalid_key = "invalid-secret-key-1234567890"

    with client:
        response = client.post(
            "/api/v1/events",
            json=event_payload(),
            headers={"X-API-Key": invalid_key},
        )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "api_key_invalid"
    assert invalid_key not in response.text
    database_engine.dispose()


def test_valid_api_key_allows_ingestion_and_reports_remaining_budget() -> None:
    database_engine, client = protected_client(request_limit=2)

    with client:
        response = client.post(
            "/api/v1/events",
            json=event_payload(),
            headers={"X-API-Key": API_KEY},
        )

    assert response.status_code == 201
    assert response.headers["X-RateLimit-Limit"] == "2"
    assert response.headers["X-RateLimit-Remaining"] == "1"
    database_engine.dispose()


def test_rate_limit_returns_429_and_retry_after() -> None:
    database_engine, client = protected_client(request_limit=2)
    headers = {"X-API-Key": API_KEY}
    payload = event_payload()

    with client:
        first = client.post("/api/v1/events", json=payload, headers=headers)
        second = client.post("/api/v1/events", json=payload, headers=headers)
        limited = client.post("/api/v1/events", json=payload, headers=headers)

    assert first.status_code == 201
    assert second.status_code == 200
    assert limited.status_code == 429
    assert limited.json()["error"]["code"] == "rate_limit_exceeded"
    assert limited.headers["X-RateLimit-Remaining"] == "0"
    assert int(limited.headers["Retry-After"]) >= 1
    database_engine.dispose()
