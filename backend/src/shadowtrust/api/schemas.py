"""Public HTTP response contracts for the ShadowTrust API."""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from shadowtrust.domain.decisions import (
    DetectionDecision,
    RecommendedAction,
    RiskLevel,
)
from shadowtrust.domain.events import SecurityEvent
from shadowtrust.domain.cases import CaseStatus


class ApiModel(BaseModel):
    """Apply one strict, immutable policy to every API response model."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class ProcessEventResponse(ApiModel):
    created: bool
    event: SecurityEvent
    decision: DetectionDecision | None


class SessionTimelineItem(ApiModel):
    event: SecurityEvent
    decision: DetectionDecision | None


class SessionTimelineResponse(ApiModel):
    session_id: UUID
    items: tuple[SessionTimelineItem, ...]


class DecisionReplayResponse(ApiModel):
    status: Literal["reproduced", "drifted", "incompatible"]
    original_decision: DetectionDecision
    replayed_decision: DetectionDecision | None
    differences: tuple[str, ...]


class SessionRiskSummary(ApiModel):
    session_id: UUID
    decision_id: UUID
    trigger_event_id: UUID
    trigger_event_type: str
    occurred_at: datetime
    risk_before: int = Field(ge=0, le=100)
    risk_after: int = Field(ge=0, le=100)
    risk_delta: int = Field(ge=-100, le=100)
    risk_level: RiskLevel
    recommended_actions: tuple[RecommendedAction, ...]
    explanation: str
    matched_rules: tuple[str, ...]
    case_id: UUID | None
    case_status: CaseStatus | None
    case_version: int | None = Field(default=None, ge=1)


class SessionCaseCounts(ApiModel):
    unassigned: int = Field(ge=0)
    open: int = Field(ge=0)
    investigating: int = Field(ge=0)
    confirmed_takeover: int = Field(ge=0)
    false_positive: int = Field(ge=0)
    closed: int = Field(ge=0)


class PaginatedSessionRiskResponse(ApiModel):
    page: int = Field(ge=1)
    page_size: int = Field(ge=1, le=100)
    total: int = Field(ge=0)
    items: tuple[SessionRiskSummary, ...]
    case_counts: SessionCaseCounts


class OpenAnalystCaseRequest(ApiModel):
    session_id: UUID
    note: str | None = Field(default=None, min_length=3, max_length=500)

    @field_validator("note", mode="before")
    @classmethod
    def normalize_note(cls, value: str | None) -> str | None:
        return value.strip() if value is not None else None


class TransitionAnalystCaseRequest(ApiModel):
    expected_version: int = Field(ge=1)
    status: CaseStatus
    note: str = Field(min_length=3, max_length=500)

    @field_validator("note", mode="before")
    @classmethod
    def normalize_note(cls, value: str) -> str:
        return value.strip()


class ValidationIssue(ApiModel):
    location: tuple[str | int, ...]
    message: str = Field(min_length=1)
    type: str = Field(min_length=1)


class ErrorDetail(ApiModel):
    code: str = Field(pattern=r"^[a-z][a-z0-9_]*$")
    message: str = Field(min_length=1)
    issues: tuple[ValidationIssue, ...] = ()


class ErrorResponse(ApiModel):
    error: ErrorDetail


class HealthResponse(ApiModel):
    status: Literal["ok"] = "ok"
