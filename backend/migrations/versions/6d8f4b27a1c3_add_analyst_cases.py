"""add analyst cases and append-only audit entries

Revision ID: 6d8f4b27a1c3
Revises: c9b108aa4eed
Create Date: 2026-10-26 14:05:00
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "6d8f4b27a1c3"
down_revision: Union[str, Sequence[str], None] = "c9b108aa4eed"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "analyst_cases",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("session_id", sa.String(length=36), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('open', 'investigating', 'confirmed_takeover', "
            "'false_positive', 'closed')",
            name="ck_analyst_cases_status",
        ),
        sa.CheckConstraint(
            "version >= 1", name="ck_analyst_cases_version_positive"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("session_id"),
    )
    with op.batch_alter_table("analyst_cases", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_analyst_cases_session_id"),
            ["session_id"],
            unique=True,
        )
        batch_op.create_index(
            batch_op.f("ix_analyst_cases_status"), ["status"], unique=False
        )
        batch_op.create_index(
            batch_op.f("ix_analyst_cases_updated_at"),
            ["updated_at"],
            unique=False,
        )

    op.create_table(
        "case_audit_entries",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("case_id", sa.String(length=36), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("previous_status", sa.String(length=32), nullable=True),
        sa.Column("new_status", sa.String(length=32), nullable=False),
        sa.Column("actor_id", sa.String(length=64), nullable=False),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "(sequence = 1 AND previous_status IS NULL) OR "
            "(sequence > 1 AND previous_status IS NOT NULL)",
            name="ck_case_audit_entries_previous_status",
        ),
        sa.CheckConstraint(
            "sequence >= 1", name="ck_case_audit_entries_sequence_positive"
        ),
        sa.ForeignKeyConstraint(
            ["case_id"], ["analyst_cases.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "case_id",
            "sequence",
            name="uq_case_audit_entries_case_sequence",
        ),
    )
    with op.batch_alter_table("case_audit_entries", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_case_audit_entries_actor_id"),
            ["actor_id"],
            unique=False,
        )
        batch_op.create_index(
            batch_op.f("ix_case_audit_entries_case_id"),
            ["case_id"],
            unique=False,
        )
        batch_op.create_index(
            batch_op.f("ix_case_audit_entries_new_status"),
            ["new_status"],
            unique=False,
        )


def downgrade() -> None:
    with op.batch_alter_table("case_audit_entries", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_case_audit_entries_new_status"))
        batch_op.drop_index(batch_op.f("ix_case_audit_entries_case_id"))
        batch_op.drop_index(batch_op.f("ix_case_audit_entries_actor_id"))
    op.drop_table("case_audit_entries")

    with op.batch_alter_table("analyst_cases", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_analyst_cases_updated_at"))
        batch_op.drop_index(batch_op.f("ix_analyst_cases_status"))
        batch_op.drop_index(batch_op.f("ix_analyst_cases_session_id"))
    op.drop_table("analyst_cases")
