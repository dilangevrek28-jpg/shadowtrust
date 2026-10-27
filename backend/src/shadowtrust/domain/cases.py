"""Immutable analyst-case workflow and audit models."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator


ActorId = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._@-]{2,63}$")]


class CaseStatus(StrEnum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    CONFIRMED_TAKEOVER = "confirmed_takeover"
    FALSE_POSITIVE = "false_positive"
    CLOSED = "closed"


ALLOWED_CASE_TRANSITIONS: dict[CaseStatus, frozenset[CaseStatus]] = {
    CaseStatus.OPEN: frozenset(
        {
            CaseStatus.INVESTIGATING,
            CaseStatus.CONFIRMED_TAKEOVER,
            CaseStatus.FALSE_POSITIVE,
            CaseStatus.CLOSED,
        }
    ),
    CaseStatus.INVESTIGATING: frozenset(
        {
            CaseStatus.CONFIRMED_TAKEOVER,
            CaseStatus.FALSE_POSITIVE,
            CaseStatus.CLOSED,
        }
    ),
    CaseStatus.CONFIRMED_TAKEOVER: frozenset(
        {CaseStatus.INVESTIGATING, CaseStatus.CLOSED}
    ),
    CaseStatus.FALSE_POSITIVE: frozenset(
        {CaseStatus.INVESTIGATING, CaseStatus.CLOSED}
    ),
    CaseStatus.CLOSED: frozenset({CaseStatus.INVESTIGATING}),
}


class CaseAuditEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: UUID
    case_id: UUID
    sequence: int = Field(ge=1)
    previous_status: CaseStatus | None
    new_status: CaseStatus
    actor_id: ActorId
    note: str | None = Field(default=None, min_length=3, max_length=500)
    occurred_at: datetime

    @model_validator(mode="after")
    def validate_audit_entry(self) -> CaseAuditEntry:
        if self.occurred_at.tzinfo is None or self.occurred_at.utcoffset() is None:
            raise ValueError("occurred_at must include timezone information")
        if self.note is not None and self.note != self.note.strip():
            raise ValueError("note cannot start or end with whitespace")
        if self.sequence == 1 and self.previous_status is not None:
            raise ValueError("opening audit entry cannot have a previous status")
        if self.sequence > 1 and self.previous_status is None:
            raise ValueError("transition audit entry must have a previous status")
        if self.previous_status == self.new_status:
            raise ValueError("audit entry must change status")
        return self


class AnalystCase(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: UUID
    session_id: UUID
    status: CaseStatus
    version: int = Field(ge=1)
    created_at: datetime
    updated_at: datetime
    audit_trail: tuple[CaseAuditEntry, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_audit_trail(self) -> AnalystCase:
        if (
            self.created_at.tzinfo is None
            or self.created_at.utcoffset() is None
            or self.updated_at.tzinfo is None
            or self.updated_at.utcoffset() is None
        ):
            raise ValueError("case timestamps must include timezone information")
        if self.updated_at < self.created_at:
            raise ValueError("updated_at cannot precede created_at")
        if len(self.audit_trail) != self.version:
            raise ValueError("version must equal the audit-trail length")
        for sequence, entry in enumerate(self.audit_trail, start=1):
            if entry.case_id != self.id or entry.sequence != sequence:
                raise ValueError("audit trail must be ordered and belong to the case")
            if sequence > 1:
                previous = self.audit_trail[sequence - 2]
                if entry.previous_status != previous.new_status:
                    raise ValueError("audit status chain is not continuous")
                if entry.new_status not in ALLOWED_CASE_TRANSITIONS[
                    previous.new_status
                ]:
                    raise ValueError("audit trail contains an invalid transition")
                if entry.occurred_at < previous.occurred_at:
                    raise ValueError("audit timestamps must be chronological")
        if self.audit_trail[0].new_status != CaseStatus.OPEN:
            raise ValueError("case must begin in open status")
        if self.audit_trail[-1].new_status != self.status:
            raise ValueError("case status must match the last audit entry")
        if self.audit_trail[0].occurred_at != self.created_at:
            raise ValueError("created_at must match the opening audit entry")
        if self.audit_trail[-1].occurred_at != self.updated_at:
            raise ValueError("updated_at must match the latest audit entry")
        return self


def transition_case(
    case: AnalystCase,
    *,
    new_status: CaseStatus,
    actor_id: str,
    note: str,
    occurred_at: datetime,
    audit_id: UUID,
) -> AnalystCase:
    """Return a new case version or reject an invalid workflow transition."""

    if new_status not in ALLOWED_CASE_TRANSITIONS[case.status]:
        raise ValueError(
            f"case cannot transition from {case.status.value} to {new_status.value}"
        )
    entry = CaseAuditEntry(
        id=audit_id,
        case_id=case.id,
        sequence=case.version + 1,
        previous_status=case.status,
        new_status=new_status,
        actor_id=actor_id,
        note=note,
        occurred_at=occurred_at,
    )
    return AnalystCase(
        id=case.id,
        session_id=case.session_id,
        status=new_status,
        version=case.version + 1,
        created_at=case.created_at,
        updated_at=occurred_at,
        audit_trail=(*case.audit_trail, entry),
    )
