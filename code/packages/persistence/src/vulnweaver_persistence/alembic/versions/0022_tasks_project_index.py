"""Index project task listings (project_id, created_at DESC)."""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
from sqlalchemy import desc

revision: str = "0022_tasks_project_index"
down_revision: str | None = "0021_poc_verification_evidence"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index(
        "ix_tasks_project_created",
        "tasks",
        ["project_id", desc("created_at")],
    )


def downgrade() -> None:
    op.drop_index("ix_tasks_project_created", table_name="tasks")
