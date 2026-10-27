import pytest
from pydantic import ValidationError

from shadowtrust.settings import RuntimeEnvironment, RuntimeSettings


def test_runtime_settings_have_safe_local_defaults() -> None:
    settings = RuntimeSettings.from_environment({})

    assert settings.environment is RuntimeEnvironment.DEVELOPMENT
    assert settings.database_url == "sqlite+pysqlite:///./shadowtrust.db"
    assert settings.database_echo is False
    assert settings.api_host == "127.0.0.1"
    assert settings.api_port == 8000
    assert settings.max_request_body_bytes == 1_048_576
    assert settings.ingestion_api_keys == ()
    assert settings.analyst_api_keys == ()
    assert settings.metrics_api_keys == ()
    assert settings.rate_limit_requests == 120
    assert settings.rate_limit_window_seconds == 60
    assert settings.log_level == "info"


def test_runtime_settings_parse_known_environment_variables() -> None:
    settings = RuntimeSettings.from_environment(
        {
            "SHADOWTRUST_ENVIRONMENT": "production",
            "SHADOWTRUST_DATABASE_URL": "postgresql+psycopg://app:secret@db/app",
            "SHADOWTRUST_DATABASE_ECHO": "true",
            "SHADOWTRUST_API_HOST": "0.0.0.0",
            "SHADOWTRUST_API_PORT": "9000",
            "SHADOWTRUST_MAX_REQUEST_BODY_BYTES": "2097152",
            "SHADOWTRUST_INGESTION_API_KEYS": (
                "production-key-value-1234,rotation-key-value-5678"
            ),
            "SHADOWTRUST_ANALYST_API_KEYS": "analyst-key-value-123456",
            "SHADOWTRUST_METRICS_API_KEYS": "metrics-key-value-123456",
            "SHADOWTRUST_RATE_LIMIT_REQUESTS": "300",
            "SHADOWTRUST_RATE_LIMIT_WINDOW_SECONDS": "120",
            "SHADOWTRUST_LOG_LEVEL": "warning",
            "UNRELATED_VARIABLE": "ignored",
        }
    )

    assert settings.environment is RuntimeEnvironment.PRODUCTION
    assert settings.database_echo is True
    assert settings.api_host == "0.0.0.0"
    assert settings.api_port == 9000
    assert settings.max_request_body_bytes == 2_097_152
    assert [key.get_secret_value() for key in settings.ingestion_api_keys] == [
        "production-key-value-1234",
        "rotation-key-value-5678",
    ]
    assert [key.get_secret_value() for key in settings.analyst_api_keys] == [
        "analyst-key-value-123456"
    ]
    assert [key.get_secret_value() for key in settings.metrics_api_keys] == [
        "metrics-key-value-123456"
    ]
    assert settings.rate_limit_requests == 300
    assert settings.rate_limit_window_seconds == 120
    assert settings.log_level == "warning"


@pytest.mark.parametrize(
    ("variable", "value"),
    [
        ("SHADOWTRUST_ENVIRONMENT", "staging"),
        ("SHADOWTRUST_DATABASE_URL", ""),
        ("SHADOWTRUST_DATABASE_ECHO", "sometimes"),
        ("SHADOWTRUST_API_PORT", "70000"),
        ("SHADOWTRUST_MAX_REQUEST_BODY_BYTES", "100"),
        ("SHADOWTRUST_RATE_LIMIT_REQUESTS", "0"),
        ("SHADOWTRUST_RATE_LIMIT_WINDOW_SECONDS", "7200"),
        ("SHADOWTRUST_LOG_LEVEL", "verbose"),
    ],
)
def test_runtime_settings_reject_invalid_values(variable: str, value: str) -> None:
    with pytest.raises(ValidationError):
        RuntimeSettings.from_environment({variable: value})


def test_runtime_settings_are_immutable() -> None:
    settings = RuntimeSettings()

    with pytest.raises(ValidationError):
        settings.api_port = 9000


def test_production_requires_an_ingestion_api_key() -> None:
    with pytest.raises(ValidationError, match="production requires"):
        RuntimeSettings.from_environment(
            {
                "SHADOWTRUST_ENVIRONMENT": "production",
                "SHADOWTRUST_ANALYST_API_KEYS": "analyst-key-value-123456",
                "SHADOWTRUST_METRICS_API_KEYS": "metrics-key-value-123456",
            }
        )


def test_production_requires_an_analyst_api_key() -> None:
    with pytest.raises(ValidationError, match="production requires.*analyst"):
        RuntimeSettings.from_environment(
            {
                "SHADOWTRUST_ENVIRONMENT": "production",
                "SHADOWTRUST_INGESTION_API_KEYS": "ingestion-key-value-1234",
                "SHADOWTRUST_METRICS_API_KEYS": "metrics-key-value-123456",
            }
        )


def test_production_requires_a_metrics_api_key() -> None:
    with pytest.raises(ValidationError, match="production requires.*metrics"):
        RuntimeSettings.from_environment(
            {
                "SHADOWTRUST_ENVIRONMENT": "production",
                "SHADOWTRUST_INGESTION_API_KEYS": "ingestion-key-value-1234",
                "SHADOWTRUST_ANALYST_API_KEYS": "analyst-key-value-123456",
            }
        )


def test_ingestion_api_keys_have_a_minimum_length_and_are_masked() -> None:
    with pytest.raises(ValidationError, match="at least 16 characters"):
        RuntimeSettings.from_environment(
            {"SHADOWTRUST_INGESTION_API_KEYS": "too-short"}
        )

    settings = RuntimeSettings.from_environment(
        {"SHADOWTRUST_INGESTION_API_KEYS": "long-enough-secret-key"}
    )
    assert "long-enough-secret-key" not in repr(settings)


def test_metrics_api_keys_have_a_minimum_length_and_are_masked() -> None:
    with pytest.raises(ValidationError, match="at least 16 characters"):
        RuntimeSettings.from_environment({"SHADOWTRUST_METRICS_API_KEYS": "short"})

    settings = RuntimeSettings.from_environment(
        {"SHADOWTRUST_METRICS_API_KEYS": "long-enough-metrics-key"}
    )
    assert "long-enough-metrics-key" not in repr(settings)
