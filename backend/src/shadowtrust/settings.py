"""Validated runtime configuration loaded from environment variables."""

from __future__ import annotations

import os
from collections.abc import Mapping
from enum import StrEnum
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator


class RuntimeEnvironment(StrEnum):
    DEVELOPMENT = "development"
    TEST = "test"
    PRODUCTION = "production"


class RuntimeSettings(BaseModel):
    """Immutable process settings; domain code never reads the environment."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    environment: RuntimeEnvironment = RuntimeEnvironment.DEVELOPMENT
    database_url: str = Field(
        default="sqlite+pysqlite:///./shadowtrust.db",
        min_length=1,
    )
    database_echo: bool = False
    api_host: str = Field(default="127.0.0.1", min_length=1)
    api_port: int = Field(default=8000, ge=1, le=65535)
    max_request_body_bytes: int = Field(
        default=1_048_576,
        ge=1_024,
        le=10_485_760,
    )
    ingestion_api_keys: tuple[SecretStr, ...] = ()
    analyst_api_keys: tuple[SecretStr, ...] = ()
    metrics_api_keys: tuple[SecretStr, ...] = ()
    rate_limit_requests: int = Field(default=120, ge=1, le=10_000)
    rate_limit_window_seconds: int = Field(default=60, ge=1, le=3_600)
    log_level: str = Field(
        default="info",
        pattern=r"^(critical|error|warning|info|debug)$",
    )

    @classmethod
    def from_environment(
        cls,
        environ: Mapping[str, str] | None = None,
    ) -> Self:
        """Read only known SHADOWTRUST_* variables and validate their values."""

        source = os.environ if environ is None else environ
        variable_names = {
            "environment": "SHADOWTRUST_ENVIRONMENT",
            "database_url": "SHADOWTRUST_DATABASE_URL",
            "database_echo": "SHADOWTRUST_DATABASE_ECHO",
            "api_host": "SHADOWTRUST_API_HOST",
            "api_port": "SHADOWTRUST_API_PORT",
            "max_request_body_bytes": "SHADOWTRUST_MAX_REQUEST_BODY_BYTES",
            "rate_limit_requests": "SHADOWTRUST_RATE_LIMIT_REQUESTS",
            "rate_limit_window_seconds": "SHADOWTRUST_RATE_LIMIT_WINDOW_SECONDS",
            "log_level": "SHADOWTRUST_LOG_LEVEL",
        }
        values = {
            field_name: source[variable_name]
            for field_name, variable_name in variable_names.items()
            if variable_name in source
        }
        if "SHADOWTRUST_INGESTION_API_KEYS" in source:
            values["ingestion_api_keys"] = tuple(
                item.strip()
                for item in source["SHADOWTRUST_INGESTION_API_KEYS"].split(",")
            )
        if "SHADOWTRUST_ANALYST_API_KEYS" in source:
            values["analyst_api_keys"] = tuple(
                item.strip()
                for item in source["SHADOWTRUST_ANALYST_API_KEYS"].split(",")
            )
        if "SHADOWTRUST_METRICS_API_KEYS" in source:
            values["metrics_api_keys"] = tuple(
                item.strip()
                for item in source["SHADOWTRUST_METRICS_API_KEYS"].split(",")
            )
        return cls.model_validate(values)

    @model_validator(mode="after")
    def validate_ingestion_authentication(self) -> Self:
        all_api_keys = (
            self.ingestion_api_keys + self.analyst_api_keys + self.metrics_api_keys
        )
        if any(len(key.get_secret_value()) < 16 for key in all_api_keys):
            raise ValueError("API keys must contain at least 16 characters")
        if (
            self.environment is RuntimeEnvironment.PRODUCTION
            and not self.ingestion_api_keys
        ):
            raise ValueError("production requires at least one ingestion API key")
        if (
            self.environment is RuntimeEnvironment.PRODUCTION
            and not self.analyst_api_keys
        ):
            raise ValueError("production requires at least one analyst API key")
        if (
            self.environment is RuntimeEnvironment.PRODUCTION
            and not self.metrics_api_keys
        ):
            raise ValueError("production requires at least one metrics API key")
        return self
