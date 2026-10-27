"""Relational persistence models for events, baselines, and decisions."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from shadowtrust.persistence.database import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class SecurityEventRecord(Base):
    __tablename__ = "security_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    session_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    device_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    schema_version: Mapped[str] = mapped_column(String(16), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    document: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    persisted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )

    __table_args__ = (
        Index("ix_security_events_session_time", "session_id", "occurred_at"),
    )


class UserBaselineRecord(Base):
    __tablename__ = "user_baselines"

    user_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    version: Mapped[str] = mapped_column(String(32), primary_key=True)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    sample_size: Mapped[int] = mapped_column(Integer, nullable=False)
    document: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    persisted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )


class DetectionDecisionRecord(Base):
    __tablename__ = "detection_decisions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    session_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    trigger_event_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("security_events.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    risk_before: Mapped[int] = mapped_column(Integer, nullable=False)
    risk_after: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    risk_level: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    recommended_actions: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    rule_set_version: Mapped[str] = mapped_column(String(32), nullable=False)
    engine_version: Mapped[str] = mapped_column(String(32), nullable=False)
    baseline_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    document: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    persisted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )

    evaluations: Mapped[list[RuleEvaluationRecord]] = relationship(
        back_populates="decision",
        cascade="all, delete-orphan",
        order_by="RuleEvaluationRecord.position",
    )


class RuleEvaluationRecord(Base):
    __tablename__ = "rule_evaluations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    decision_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("detection_decisions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    position: Mapped[int] = mapped_column(Integer, nullable=False)
    rule_code: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    rule_version: Mapped[str] = mapped_column(String(32), nullable=False)
    category: Mapped[str] = mapped_column(String(32), nullable=False)
    matched: Mapped[bool] = mapped_column(Boolean, nullable=False, index=True)
    score_delta: Mapped[int] = mapped_column(Integer, nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_event_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False)

    decision: Mapped[DetectionDecisionRecord] = relationship(
        back_populates="evaluations"
    )

    __table_args__ = (
        UniqueConstraint(
            "decision_id",
            "position",
            name="uq_rule_evaluations_decision_position",
        ),
    )


class AnalystCaseRecord(Base):
    __tablename__ = "analyst_cases"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    session_id: Mapped[str] = mapped_column(
        String(36), nullable=False, unique=True, index=True
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )

    audit_entries: Mapped[list[CaseAuditRecord]] = relationship(
        back_populates="case",
        cascade="save-update, merge",
        order_by="CaseAuditRecord.sequence",
    )

    __table_args__ = (
        CheckConstraint("version >= 1", name="ck_analyst_cases_version_positive"),
        CheckConstraint(
            "status IN ('open', 'investigating', 'confirmed_takeover', "
            "'false_positive', 'closed')",
            name="ck_analyst_cases_status",
        ),
    )


class CaseAuditRecord(Base):
    __tablename__ = "case_audit_entries"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    case_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("analyst_cases.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    previous_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    new_status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    actor_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    case: Mapped[AnalystCaseRecord] = relationship(back_populates="audit_entries")

    __table_args__ = (
        CheckConstraint(
            "sequence >= 1", name="ck_case_audit_entries_sequence_positive"
        ),
        CheckConstraint(
            "(sequence = 1 AND previous_status IS NULL) OR "
            "(sequence > 1 AND previous_status IS NOT NULL)",
            name="ck_case_audit_entries_previous_status",
        ),
        UniqueConstraint(
            "case_id",
            "sequence",
            name="uq_case_audit_entries_case_sequence",
        ),
    )
