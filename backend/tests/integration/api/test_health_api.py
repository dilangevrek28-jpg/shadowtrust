from uuid import UUID, uuid4

from fastapi.testclient import TestClient

from shadowtrust.api import create_app
from shadowtrust.persistence import (
    build_session_factory,
    create_database_engine,
    create_schema,
)


def test_health_endpoints_report_live_and_ready() -> None:
    database_engine = create_database_engine()
    create_schema(database_engine)
    app = create_app(build_session_factory(database_engine))

    with TestClient(app) as client:
        live_response = client.get("/health/live")
        ready_response = client.get("/health/ready")

    assert live_response.status_code == 200
    assert live_response.json() == {"status": "ok"}
    assert ready_response.status_code == 200
    assert ready_response.json() == {"status": "ok"}
    database_engine.dispose()


def test_readiness_fails_when_database_schema_is_missing() -> None:
    database_engine = create_database_engine()
    app = create_app(build_session_factory(database_engine))

    with TestClient(app) as client:
        live_response = client.get("/health/live")
        ready_response = client.get("/health/ready")

    assert live_response.status_code == 200
    assert ready_response.status_code == 503
    assert ready_response.json() == {
        "error": {
            "code": "database_not_ready",
            "message": "Database connection or schema is not ready.",
        }
    }
    database_engine.dispose()


def test_request_id_is_preserved_when_client_supplies_a_valid_uuid() -> None:
    database_engine = create_database_engine()
    create_schema(database_engine)
    app = create_app(build_session_factory(database_engine))
    request_id = str(uuid4())

    with TestClient(app) as client:
        response = client.get(
            "/health/live",
            headers={"X-Request-ID": request_id},
        )

    assert response.status_code == 200
    assert response.headers["X-Request-ID"] == request_id
    database_engine.dispose()


def test_invalid_request_id_is_replaced_with_a_server_generated_uuid() -> None:
    database_engine = create_database_engine()
    create_schema(database_engine)
    app = create_app(build_session_factory(database_engine))

    with TestClient(app) as client:
        response = client.get(
            "/health/live",
            headers={"X-Request-ID": "unsafe value with spaces"},
        )

    generated_request_id = response.headers["X-Request-ID"]
    assert str(UUID(generated_request_id)) == generated_request_id
    assert generated_request_id != "unsafe value with spaces"
    database_engine.dispose()
