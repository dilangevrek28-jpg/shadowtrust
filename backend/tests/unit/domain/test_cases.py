from datetime import datetime, timedelta, timezone
from uuid import UUID

import pytest
from pydantic import ValidationError

from shadowtrust.domain.cases import (
    AnalystCase,
    CaseAuditEntry,
    CaseStatus,
    transition_case,
)


CASE_ID = UUID("00000000-0000-4000-8000-000000000101")
SESSION_ID = UUID("00000000-0000-4000-8000-000000000102")
OPEN_AUDIT_ID = UUID("00000000-0000-4000-8000-000000000103")
TRANSITION_AUDIT_ID = UUID("00000000-0000-4000-8000-000000000104")
OPENED_AT = datetime(2026, 10, 26, 14, 0, tzinfo=timezone.utc)


def open_case() -> AnalystCase:
    audit = CaseAuditEntry(
        id=OPEN_AUDIT_ID,
        case_id=CASE_ID,
        sequence=1,
        previous_status=None,
        new_status=CaseStatus.OPEN,
        actor_id="analyst.one",
        note="Initial triage requested.",
        occurred_at=OPENED_AT,
    )
    return AnalystCase(
        id=CASE_ID,
        session_id=SESSION_ID,
        status=CaseStatus.OPEN,
        version=1,
        created_at=OPENED_AT,
        updated_at=OPENED_AT,
        audit_trail=(audit,),
    )


def test_valid_transition_returns_a_new_audited_case_version() -> None:
    original = open_case()
    changed_at = OPENED_AT + timedelta(minutes=5)

    updated = transition_case(
        original,
        new_status=CaseStatus.INVESTIGATING,
        actor_id="analyst.two",
        note="Customer verification started.",
        occurred_at=changed_at,
        audit_id=TRANSITION_AUDIT_ID,
    )

    assert original.status == CaseStatus.OPEN
    assert updated.status == CaseStatus.INVESTIGATING
    assert updated.version == 2
    assert updated.audit_trail[-1].previous_status == CaseStatus.OPEN
    assert updated.audit_trail[-1].actor_id == "analyst.two"
    assert updated.updated_at == changed_at


def test_same_status_and_disallowed_transition_are_rejected() -> None:
    case = open_case()

    with pytest.raises(ValueError, match="cannot transition"):
        transition_case(
            case,
            new_status=CaseStatus.OPEN,
            actor_id="analyst.one",
            note="No valid state change.",
            occurred_at=OPENED_AT + timedelta(minutes=1),
            audit_id=TRANSITION_AUDIT_ID,
        )

    confirmed = transition_case(
        case,
        new_status=CaseStatus.CONFIRMED_TAKEOVER,
        actor_id="analyst.one",
        note="Takeover evidence was confirmed.",
        occurred_at=OPENED_AT + timedelta(minutes=1),
        audit_id=TRANSITION_AUDIT_ID,
    )
    with pytest.raises(ValueError, match="cannot transition"):
        transition_case(
            confirmed,
            new_status=CaseStatus.FALSE_POSITIVE,
            actor_id="analyst.one",
            note="Contradictory classification is not direct.",
            occurred_at=OPENED_AT + timedelta(minutes=2),
            audit_id=UUID("00000000-0000-4000-8000-000000000105"),
        )


def test_audit_chain_cannot_skip_a_sequence() -> None:
    opening = open_case().audit_trail[0]
    broken = CaseAuditEntry(
        id=TRANSITION_AUDIT_ID,
        case_id=CASE_ID,
        sequence=3,
        previous_status=CaseStatus.OPEN,
        new_status=CaseStatus.INVESTIGATING,
        actor_id="analyst.two",
        note="Sequence was intentionally broken.",
        occurred_at=OPENED_AT + timedelta(minutes=1),
    )

    with pytest.raises(ValidationError, match="ordered"):
        AnalystCase(
            id=CASE_ID,
            session_id=SESSION_ID,
            status=CaseStatus.INVESTIGATING,
            version=2,
            created_at=OPENED_AT,
            updated_at=broken.occurred_at,
            audit_trail=(opening, broken),
        )


def test_audit_timestamp_must_be_timezone_aware() -> None:
    with pytest.raises(ValidationError, match="timezone"):
        CaseAuditEntry(
            id=OPEN_AUDIT_ID,
            case_id=CASE_ID,
            sequence=1,
            previous_status=None,
            new_status=CaseStatus.OPEN,
            actor_id="analyst.one",
            occurred_at=OPENED_AT.replace(tzinfo=None),
        )
