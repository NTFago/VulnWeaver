"""Add a terminal state for non-retryable Outbox failures.

Revision ID: 0002_outbox_dead_letter
Revises: 0001_control_plane_core
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002_outbox_dead_letter"
down_revision: str | None = "0001_control_plane_core"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "outbox_events",
        sa.Column("dead_lettered_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "outbox_events",
        sa.Column(
            "dead_letter_reason",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
    )
    op.create_check_constraint(
        op.f("ck_outbox_events_single_terminal_state"),
        "outbox_events",
        "NOT (published_at IS NOT NULL AND dead_lettered_at IS NOT NULL)",
    )
    op.drop_index("ix_outbox_events_pending", table_name="outbox_events")
    op.create_index(
        "ix_outbox_events_pending",
        "outbox_events",
        ["available_at", "created_at"],
        unique=False,
        postgresql_where=sa.text("published_at IS NULL AND dead_lettered_at IS NULL"),
    )


def downgrade() -> None:
    op.drop_index("ix_outbox_events_pending", table_name="outbox_events")
    op.create_index(
        "ix_outbox_events_pending",
        "outbox_events",
        ["available_at", "created_at"],
        unique=False,
        postgresql_where=sa.text("published_at IS NULL"),
    )
    op.drop_constraint(
        op.f("ck_outbox_events_single_terminal_state"),
        "outbox_events",
        type_="check",
    )
    op.drop_column("outbox_events", "dead_letter_reason")
    op.drop_column("outbox_events", "dead_lettered_at")
