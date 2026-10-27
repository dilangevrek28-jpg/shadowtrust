"""Synthetic user-behaviour baselines used by explainable rules."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


CountryCode = Annotated[str, Field(pattern=r"^[A-Z]{2}$")]


class UserBaseline(BaseModel):
    """Immutable snapshot of behaviour known before detection runs."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    user_id: UUID
    version: str = Field(min_length=1, max_length=32)
    generated_at: datetime
    sample_size: int = Field(ge=0)
    known_device_ids: frozenset[UUID] = frozenset()
    known_countries: frozenset[CountryCode] = frozenset()

    @field_validator("generated_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("baseline timestamp must include a timezone offset")
        return value

    @field_validator("known_countries", mode="before")
    @classmethod
    def normalize_countries(cls, value: object) -> object:
        if isinstance(value, (list, tuple, set, frozenset)):
            return frozenset(
                item.upper() if isinstance(item, str) else item for item in value
            )
        return value
