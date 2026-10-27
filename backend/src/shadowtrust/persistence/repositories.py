"""Repositories translating between domain models and SQLAlchemy records."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session, selectinload

from shadowtrust.domain.baselines import UserBaseline
from shadowtrust.domain.cases import AnalystCase, CaseAuditEntry, CaseStatus
from shadowtrust.domain.decisions import DetectionDecision, RiskLevel
from shadowtrust.domain.events import SecurityEvent, parse_security_event
from shadowtrust.persistence.models import (
    AnalystCaseRecord,
    CaseAuditRecord,
    DetectionDecisionRecord,
    RuleEvaluationRecord,
    SecurityEventRecord,
    UserBaselineRecord,
)


class ConcurrentCaseUpdateError(RuntimeError):
    """The persisted case version changed before the update was applied."""


def _as_utc(value: datetime) -> datetime:
    """Restore UTC tzinfo lost by SQLite while preserving aware DB values."""

    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


@dataclass(frozen=True, slots=True)
class SessionRiskSnapshot:
    decision: DetectionDecision
    trigger_event: SecurityEvent
    case_id: UUID | None
    case_status: CaseStatus | None
    case_version: int | None


@dataclass(frozen=True, slots=True)
class SessionCaseCounts:
    unassigned: int = 0
    open: int = 0
    investigating: int = 0
    confirmed_takeover: int = 0
    false_positive: int = 0
    closed: int = 0


class SecurityEventRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, event: SecurityEvent) -> None:
        self._session.add(
            SecurityEventRecord(
                id=str(event.id),
                user_id=str(event.user_id),
                session_id=str(event.session_id) if event.session_id else None,
                device_id=str(event.device_id) if event.device_id else None,
                event_type=event.event_type,
                schema_version=event.schema_version,
                occurred_at=event.occurred_at,
                received_at=event.received_at,
                document=event.model_dump(mode="json"),
            )
        )
        self._session.flush()

    def get(self, event_id: UUID) -> SecurityEvent | None:
        record = self._session.get(SecurityEventRecord, str(event_id))
        if record is None:
            return None
        return parse_security_event(record.document)

    def list_for_session(self, session_id: UUID) -> tuple[SecurityEvent, ...]:
        records = self._session.scalars(
            select(SecurityEventRecord)
            .where(SecurityEventRecord.session_id == str(session_id))
            .order_by(SecurityEventRecord.occurred_at, SecurityEventRecord.id)
        )
        return tuple(parse_security_event(record.document) for record in records)


class UserBaselineRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, baseline: UserBaseline) -> None:
        self._session.add(
            UserBaselineRecord(
                user_id=str(baseline.user_id),
                version=baseline.version,
                generated_at=baseline.generated_at,
                sample_size=baseline.sample_size,
                document=baseline.model_dump(mode="json"),
            )
        )
        self._session.flush()

    def get(self, user_id: UUID, version: str) -> UserBaseline | None:
        record = self._session.get(UserBaselineRecord, (str(user_id), version))
        if record is None:
            return None
        return UserBaseline.model_validate(record.document)

    def get_latest(self, user_id: UUID) -> UserBaseline | None:
        record = self._session.scalar(
            select(UserBaselineRecord)
            .where(UserBaselineRecord.user_id == str(user_id))
            .order_by(UserBaselineRecord.generated_at.desc())
            .limit(1)
        )
        if record is None:
            return None
        return UserBaseline.model_validate(record.document)


class DetectionDecisionRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, decision: DetectionDecision) -> None:
        record = DetectionDecisionRecord(
            id=str(decision.id),
            session_id=str(decision.session_id),
            trigger_event_id=str(decision.trigger_event_id),
            risk_before=decision.risk_before,
            risk_after=decision.risk_after,
            risk_level=decision.risk_level.value,
            recommended_actions=[action.value for action in decision.recommended_actions],
            explanation=decision.explanation,
            rule_set_version=decision.rule_set_version,
            engine_version=decision.engine_version,
            baseline_version=decision.baseline_version,
            document=decision.model_dump(
                mode="json",
                exclude={"risk_delta", "risk_level"},
            ),
            evaluations=[
                RuleEvaluationRecord(
                    position=position,
                    rule_code=evaluation.rule_code,
                    rule_version=evaluation.rule_version,
                    category=evaluation.category.value,
                    matched=evaluation.matched,
                    score_delta=evaluation.score_delta,
                    reason=evaluation.reason,
                    evidence_event_ids=[
                        str(event_id) for event_id in evaluation.evidence_event_ids
                    ],
                )
                for position, evaluation in enumerate(decision.evaluations)
            ],
        )
        self._session.add(record)
        self._session.flush()

    def get(self, decision_id: UUID) -> DetectionDecision | None:
        record = self._session.scalar(
            select(DetectionDecisionRecord)
            .options(selectinload(DetectionDecisionRecord.evaluations))
            .where(DetectionDecisionRecord.id == str(decision_id))
        )
        if record is None:
            return None
        return DetectionDecision.model_validate(record.document)

    def get_for_trigger(self, trigger_event_id: UUID) -> DetectionDecision | None:
        record = self._session.scalar(
            select(DetectionDecisionRecord)
            .where(
                DetectionDecisionRecord.trigger_event_id == str(trigger_event_id)
            )
            .order_by(
                DetectionDecisionRecord.persisted_at.desc(),
                DetectionDecisionRecord.id.desc(),
            )
            .limit(1)
        )
        if record is None:
            return None
        return DetectionDecision.model_validate(record.document)

    def get_latest_for_session(
        self, session_id: UUID
    ) -> DetectionDecision | None:
        record = self._session.scalar(
            select(DetectionDecisionRecord)
            .where(DetectionDecisionRecord.session_id == str(session_id))
            .order_by(
                DetectionDecisionRecord.persisted_at.desc(),
                DetectionDecisionRecord.id.desc(),
            )
            .limit(1)
        )
        if record is None:
            return None
        return DetectionDecision.model_validate(record.document)

    def list_for_session(self, session_id: UUID) -> tuple[DetectionDecision, ...]:
        records = self._session.scalars(
            select(DetectionDecisionRecord)
            .where(DetectionDecisionRecord.session_id == str(session_id))
            .order_by(DetectionDecisionRecord.persisted_at, DetectionDecisionRecord.id)
        )
        return tuple(
            DetectionDecision.model_validate(record.document) for record in records
        )

    def search_latest_by_session(
        self,
        *,
        minimum_risk: int,
        risk_level: RiskLevel | None,
        case_status: CaseStatus | None,
        unassigned_only: bool,
        offset: int,
        limit: int,
    ) -> tuple[tuple[SessionRiskSnapshot, ...], int, SessionCaseCounts]:
        ranked = (
            select(
                DetectionDecisionRecord.id.label("decision_id"),
                DetectionDecisionRecord.risk_after,
                DetectionDecisionRecord.risk_level,
                DetectionDecisionRecord.persisted_at,
                func.row_number()
                .over(
                    partition_by=DetectionDecisionRecord.session_id,
                    order_by=(
                        DetectionDecisionRecord.persisted_at.desc(),
                        DetectionDecisionRecord.id.desc(),
                    ),
                )
                .label("position"),
            )
            .subquery()
        )
        risk_filters = [
            ranked.c.position == 1,
            ranked.c.risk_after >= minimum_risk,
        ]
        if risk_level is not None:
            risk_filters.append(ranked.c.risk_level == risk_level.value)

        count_rows = self._session.execute(
            select(AnalystCaseRecord.status, func.count())
            .select_from(ranked)
            .join(
                DetectionDecisionRecord,
                DetectionDecisionRecord.id == ranked.c.decision_id,
            )
            .outerjoin(
                AnalystCaseRecord,
                AnalystCaseRecord.session_id == DetectionDecisionRecord.session_id,
            )
            .where(*risk_filters)
            .group_by(AnalystCaseRecord.status)
        ).all()
        raw_counts = {(status or "unassigned"): int(count) for status, count in count_rows}
        case_counts = SessionCaseCounts(
            **{
                field: raw_counts.get(field, 0)
                for field in SessionCaseCounts.__dataclass_fields__
            }
        )

        filters = list(risk_filters)
        if unassigned_only:
            filters.append(AnalystCaseRecord.id.is_(None))
        elif case_status is not None:
            filters.append(AnalystCaseRecord.status == case_status.value)

        total = self._session.scalar(
            select(func.count())
            .select_from(ranked)
            .join(
                DetectionDecisionRecord,
                DetectionDecisionRecord.id == ranked.c.decision_id,
            )
            .outerjoin(
                AnalystCaseRecord,
                AnalystCaseRecord.session_id == DetectionDecisionRecord.session_id,
            )
            .where(*filters)
        )
        rows = self._session.execute(
            select(
                DetectionDecisionRecord,
                SecurityEventRecord,
                AnalystCaseRecord,
            )
            .join(ranked, ranked.c.decision_id == DetectionDecisionRecord.id)
            .join(
                SecurityEventRecord,
                SecurityEventRecord.id
                == DetectionDecisionRecord.trigger_event_id,
            )
            .outerjoin(
                AnalystCaseRecord,
                AnalystCaseRecord.session_id == DetectionDecisionRecord.session_id,
            )
            .where(*filters)
            .order_by(
                ranked.c.risk_after.desc(),
                ranked.c.persisted_at.desc(),
                ranked.c.decision_id.desc(),
            )
            .offset(offset)
            .limit(limit)
        ).all()
        snapshots = tuple(
            SessionRiskSnapshot(
                decision=DetectionDecision.model_validate(decision.document),
                trigger_event=parse_security_event(event.document),
                case_id=UUID(case.id) if case else None,
                case_status=CaseStatus(case.status) if case else None,
                case_version=case.version if case else None,
            )
            for decision, event, case in rows
        )
        return snapshots, int(total or 0), case_counts


class AnalystCaseRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, case: AnalystCase) -> None:
        self._session.add(
            AnalystCaseRecord(
                id=str(case.id),
                session_id=str(case.session_id),
                status=case.status.value,
                version=case.version,
                created_at=case.created_at,
                updated_at=case.updated_at,
                audit_entries=[self._audit_record(item) for item in case.audit_trail],
            )
        )
        self._session.flush()

    def get(self, case_id: UUID) -> AnalystCase | None:
        record = self._session.scalar(
            select(AnalystCaseRecord)
            .options(selectinload(AnalystCaseRecord.audit_entries))
            .where(AnalystCaseRecord.id == str(case_id))
        )
        return self._to_domain(record) if record is not None else None

    def get_for_session(self, session_id: UUID) -> AnalystCase | None:
        record = self._session.scalar(
            select(AnalystCaseRecord)
            .options(selectinload(AnalystCaseRecord.audit_entries))
            .where(AnalystCaseRecord.session_id == str(session_id))
        )
        return self._to_domain(record) if record is not None else None

    def apply_transition(
        self,
        case: AnalystCase,
        *,
        expected_version: int,
    ) -> None:
        result = self._session.execute(
            update(AnalystCaseRecord)
            .where(
                AnalystCaseRecord.id == str(case.id),
                AnalystCaseRecord.version == expected_version,
            )
            .values(
                status=case.status.value,
                version=case.version,
                updated_at=case.updated_at,
            )
        )
        if result.rowcount != 1:
            raise ConcurrentCaseUpdateError("analyst case version changed")
        self._session.add(self._audit_record(case.audit_trail[-1]))
        self._session.flush()

    @staticmethod
    def _audit_record(entry: CaseAuditEntry) -> CaseAuditRecord:
        return CaseAuditRecord(
            id=str(entry.id),
            case_id=str(entry.case_id),
            sequence=entry.sequence,
            previous_status=(
                entry.previous_status.value if entry.previous_status else None
            ),
            new_status=entry.new_status.value,
            actor_id=entry.actor_id,
            note=entry.note,
            occurred_at=entry.occurred_at,
        )

    @staticmethod
    def _to_domain(record: AnalystCaseRecord) -> AnalystCase:
        return AnalystCase(
            id=UUID(record.id),
            session_id=UUID(record.session_id),
            status=CaseStatus(record.status),
            version=record.version,
            created_at=_as_utc(record.created_at),
            updated_at=_as_utc(record.updated_at),
            audit_trail=tuple(
                CaseAuditEntry(
                    id=UUID(entry.id),
                    case_id=UUID(entry.case_id),
                    sequence=entry.sequence,
                    previous_status=(
                        CaseStatus(entry.previous_status)
                        if entry.previous_status
                        else None
                    ),
                    new_status=CaseStatus(entry.new_status),
                    actor_id=entry.actor_id,
                    note=entry.note,
                    occurred_at=_as_utc(entry.occurred_at),
                )
                for entry in record.audit_entries
            ),
        )
