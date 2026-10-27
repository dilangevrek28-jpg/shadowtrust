"""Transactional analyst-case use cases."""

from __future__ import annotations

from collections.abc import Callable
import logging
from datetime import datetime, timezone
from uuid import UUID, uuid4

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from shadowtrust.domain.cases import (
    AnalystCase,
    CaseAuditEntry,
    CaseStatus,
    transition_case,
)
from shadowtrust.persistence import (
    AnalystCaseRepository,
    ConcurrentCaseUpdateError,
    DetectionDecisionRepository,
    transactional_session,
)
from shadowtrust.observability import log_structured


logger = logging.getLogger("shadowtrust.application.case_management")


class CaseNotFoundError(LookupError):
    pass


class CaseAlreadyExistsError(RuntimeError):
    pass


class CaseSessionNotFoundError(LookupError):
    pass


class CaseVersionConflictError(RuntimeError):
    pass


class InvalidCaseTransitionError(ValueError):
    pass


class CaseManagementService:
    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        clock: Callable[[], datetime] | None = None,
        id_factory: Callable[[], UUID] | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._id_factory = id_factory or uuid4

    def open_case(
        self,
        *,
        session_id: UUID,
        actor_id: str,
        note: str | None,
    ) -> AnalystCase:
        case_id = self._id_factory()
        audit_id = self._id_factory()
        occurred_at = self._clock()
        opening = CaseAuditEntry(
            id=audit_id,
            case_id=case_id,
            sequence=1,
            previous_status=None,
            new_status=CaseStatus.OPEN,
            actor_id=actor_id,
            note=note,
            occurred_at=occurred_at,
        )
        case = AnalystCase(
            id=case_id,
            session_id=session_id,
            status=CaseStatus.OPEN,
            version=1,
            created_at=occurred_at,
            updated_at=occurred_at,
            audit_trail=(opening,),
        )

        try:
            with transactional_session(self._session_factory) as session:
                decisions = DetectionDecisionRepository(session)
                cases = AnalystCaseRepository(session)
                if decisions.get_latest_for_session(session_id) is None:
                    raise CaseSessionNotFoundError(
                        "cannot open a case for a session without a decision"
                    )
                if cases.get_for_session(session_id) is not None:
                    raise CaseAlreadyExistsError(
                        "an analyst case already exists for this session"
                    )
                cases.add(case)
        except IntegrityError as exc:
            raise CaseAlreadyExistsError(
                "an analyst case already exists for this session"
            ) from exc
        log_structured(
            logger,
            logging.INFO,
            "analyst_case_opened",
            case_id=str(case.id),
            session_id=str(case.session_id),
            actor_id=actor_id,
            status=case.status.value,
            version=case.version,
        )
        return case

    def get_case(self, case_id: UUID) -> AnalystCase:
        with transactional_session(self._session_factory) as session:
            case = AnalystCaseRepository(session).get(case_id)
        if case is None:
            raise CaseNotFoundError("analyst case not found")
        return case

    def get_case_for_session(self, session_id: UUID) -> AnalystCase:
        with transactional_session(self._session_factory) as session:
            case = AnalystCaseRepository(session).get_for_session(session_id)
        if case is None:
            raise CaseNotFoundError("analyst case not found")
        return case

    def transition(
        self,
        *,
        case_id: UUID,
        expected_version: int,
        new_status: CaseStatus,
        actor_id: str,
        note: str,
    ) -> AnalystCase:
        with transactional_session(self._session_factory) as session:
            repository = AnalystCaseRepository(session)
            current = repository.get(case_id)
            if current is None:
                raise CaseNotFoundError("analyst case not found")
            if current.version != expected_version:
                raise CaseVersionConflictError(
                    "analyst case was changed by another request"
                )
            try:
                updated = transition_case(
                    current,
                    new_status=new_status,
                    actor_id=actor_id,
                    note=note,
                    occurred_at=self._clock(),
                    audit_id=self._id_factory(),
                )
                repository.apply_transition(
                    updated,
                    expected_version=expected_version,
                )
            except ConcurrentCaseUpdateError as exc:
                raise CaseVersionConflictError(
                    "analyst case was changed by another request"
                ) from exc
            except ValueError as exc:
                raise InvalidCaseTransitionError(str(exc)) from exc
        log_structured(
            logger,
            logging.INFO,
            "analyst_case_transitioned",
            case_id=str(updated.id),
            session_id=str(updated.session_id),
            actor_id=actor_id,
            previous_status=current.status.value,
            new_status=updated.status.value,
            version=updated.version,
        )
        return updated
