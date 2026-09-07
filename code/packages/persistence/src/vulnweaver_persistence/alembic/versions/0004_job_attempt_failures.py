"""Persist append-only retryable Job attempt failures.

Revision ID: 0004_job_attempt_failures
Revises: 0003_job_results
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004_job_attempt_failures"
down_revision: str | None = "0003_job_results"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "job_attempt_failures",
        sa.Column("job_id", sa.String(length=128), nullable=False),
        sa.Column("attempt", sa.Integer(), nullable=False),
        sa.Column("schema_version", sa.String(length=16), nullable=False),
        sa.Column("owner", sa.String(length=128), nullable=False),
        sa.Column(
            "failure",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column("failure_fingerprint", sa.String(length=64), nullable=False),
        sa.Column(
            "recorded_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "attempt > 0",
            name=op.f("ck_job_attempt_failures_attempt_positive"),
        ),
        sa.CheckConstraint(
            "schema_version = '1.0.0'",
            name=op.f("ck_job_attempt_failures_schema_version_v1"),
        ),
        sa.ForeignKeyConstraint(
            ["job_id"],
            ["jobs.id"],
            name=op.f("fk_job_attempt_failures_job_id_jobs"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint(
            "job_id",
            "attempt",
            name=op.f("pk_job_attempt_failures"),
        ),
    )


def downgrade() -> None:
    op.drop_table("job_attempt_failures")
