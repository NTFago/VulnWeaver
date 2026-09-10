"""Add the Task-level structured failure column."""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0019_task_failure"
down_revision: str | None = "0018_finding_call_path"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "tasks",
        sa.Column("failure", postgresql.JSONB, nullable=True),
    )


def downgrade() -> None:
    op.drop_column("tasks", "failure")
