from uuid import UUID

from fastapi.testclient import TestClient

from shadowtrust.api import create_app
from shadowtrust.persistence import (
    build_session_factory,
    create_database_engine,
    create_schema,
)
from shadowtrust.synthetic import generate_scenarios


def build_test_client(*, max_request_body_bytes: int = 1_048_576):
    database_engine = create_database_engine()
    create_schema(database_engine)
    app = create_app(
        build_session_factory(database_engine),
        max_request_body_bytes=max_request_body_bytes,
    )
    return database_engine, app, TestClient(app)


def test_validation_error_has_stable_shape_without_echoing_input() -> None:
    database_engine, _app, client = build_test_client()
    event = generate_scenarios()[0].events[0]
    payload = event.model_dump(mode="json")
    payload["payload"]["authentication_method"] = "stolen-secret-value"

    with client:
        response = client.post("/api/v1/events", json=payload)

    assert response.status_code == 422
    body = response.json()
    assert body["error"]["code"] == "request_validation_failed"
    assert body["error"]["message"] == "Request validation failed."
    assert body["error"]["issues"]
    assert set(body["error"]["issues"][0]) == {"location", "message", "type"}
    assert "stolen-secret-value" not in response.text
    database_engine.dispose()


def test_oversized_request_is_rejected_before_domain_processing() -> None:
    database_engine, _app, client = build_test_client(
        max_request_body_bytes=1_024
    )
    event = generate_scenarios()[0].events[0]
    payload = event.model_dump(mode="json")
    payload["padding"] = "x" * 2_000

    with client:
        response = client.post("/api/v1/events", json=payload)

    assert response.status_code == 413
    assert response.json() == {
        "error": {
            "code": "request_body_too_large",
            "message": "Request body exceeds the configured size limit.",
        }
    }
    assert str(UUID(response.headers["X-Request-ID"])) == response.headers[
        "X-Request-ID"
    ]
    database_engine.dispose()


def test_security_headers_are_attached_to_success_and_error_responses() -> None:
    database_engine, _app, client = build_test_client()

    with client:
        success = client.get("/health/live")
        error = client.get("/api/v1/events/not-a-uuid")

    for response in (success, error):
        assert response.headers["Cache-Control"] == "no-store"
        assert response.headers["Permissions-Policy"] == (
            "camera=(), microphone=(), geolocation=()"
        )
        assert response.headers["Referrer-Policy"] == "no-referrer"
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"
    database_engine.dispose()


def test_unexpected_exception_returns_generic_non_sensitive_error() -> None:
    database_engine, app, _client = build_test_client()

    @app.get("/_test/unexpected-error")
    def raise_unexpected_error():
        raise RuntimeError("database password is top-secret")

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/_test/unexpected-error")

    assert response.status_code == 500
    assert response.json() == {
        "error": {
            "code": "internal_server_error",
            "message": "An unexpected server error occurred.",
        }
    }
    assert "top-secret" not in response.text
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    database_engine.dispose()
