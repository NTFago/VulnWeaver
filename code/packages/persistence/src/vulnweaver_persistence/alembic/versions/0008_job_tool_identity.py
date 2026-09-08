"""Persist structured Job tool identity and arguments."""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0008_job_tool_identity"
down_revision: str | None = "0007_agent_runs_checkpoints"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "jobs",
        sa.Column("tool", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )
    op.add_column(
        "jobs",
        sa.Column("arguments", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("jobs", "arguments")
    op.drop_column("jobs", "tool")
