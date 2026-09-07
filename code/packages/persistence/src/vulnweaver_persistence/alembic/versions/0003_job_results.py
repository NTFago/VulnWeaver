"""Persist immutable terminal Worker results.

Revision ID: 0003_job_results
Revises: 0002_outbox_dead_letter
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0003_job_results"
down_revision: str | None = "0002_outbox_dead_letter"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "job_results",
        sa.Column("job_id", sa.String(length=128), nullable=False),
        sa.Column("schema_version", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column(
            "produced_artifact_version_ids",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column(
            "evidence_ids",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column(
            "failure",
            postgresql.JSONB(astext_type=sa.Text(), none_as_null=True),
            nullable=True,
        ),
        sa.Column("result_fingerprint", sa.String(length=64), nullable=False),
        sa.Column(
            "completed_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "(status = 'failed' AND failure IS NOT NULL) OR "
            "(status <> 'failed' AND failure IS NULL)",
            name=op.f("ck_job_results_failure_matches_status"),
        ),
        sa.CheckConstraint(
            "schema_version = '1.0.0'",
            name=op.f("ck_job_results_schema_version_v1"),
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'queued', 'running', 'waiting_permission', "
            "'succeeded', 'failed', 'cancelled')",
            name=op.f("ck_job_results_status"),
        ),
        sa.CheckConstraint(
            "status IN ('succeeded', 'failed', 'cancelled')",
            name=op.f("ck_job_results_terminal_status"),
        ),
        sa.ForeignKeyConstraint(
            ["job_id"],
            ["jobs.id"],
            name=op.f("fk_job_results_job_id_jobs"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("job_id", name=op.f("pk_job_results")),
    )


def downgrade() -> None:
    op.drop_table("job_results")
