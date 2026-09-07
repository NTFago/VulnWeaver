"""Persist the earliest time at which a Job retry may be claimed.

Revision ID: 0005_job_retry_schedule
Revises: 0004_job_attempt_failures
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005_job_retry_schedule"
down_revision: str | None = "0004_job_attempt_failures"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "jobs",
        sa.Column("retry_not_before", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("jobs", "retry_not_before")
