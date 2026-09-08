"""Create immutable Evidence facts."""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0010_evidence"
down_revision: str | None = "0009_pair_tables"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "evidence",
        sa.Column("id", sa.String(128), nullable=False),
        sa.Column("schema_version", sa.String(16), nullable=False),
        sa.Column("type", sa.String(64), nullable=False),
        sa.Column("strength", sa.String(32), nullable=False),
        sa.Column("artifact_ref", sa.Text(), nullable=False),
        sa.Column("digest", sa.String(71), nullable=False),
        sa.Column("tool", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("input_ref", sa.Text(), nullable=False),
        sa.Column("command_hash", sa.String(71), nullable=True),
        sa.Column("exit_code", sa.Integer(), nullable=True),
        sa.Column("stdout_ref", sa.Text(), nullable=True),
        sa.Column("stderr_ref", sa.Text(), nullable=True),
        sa.Column("replay_recipe", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("schema_version = '1.0.0'", name="schema_version_v1"),
        sa.CheckConstraint(
            "type IN ('model_explanation', 'tool_output', 'code_snippet', "
            "'dataflow_path', 'crash_record', 'reproduction_result', "
            "'exploit_record', 'review_conclusion', 'human_confirmation')",
            name="type",
        ),
        sa.CheckConstraint("strength IN ('contextual', 'supporting', 'strong')", name="strength"),
        sa.CheckConstraint("digest ~ '^sha256:[0-9a-f]{64}$'", name="sha256_digest"),
        sa.CheckConstraint(
            "command_hash IS NULL OR command_hash ~ '^sha256:[0-9a-f]{64}$'",
            name="command_sha256_digest",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_evidence"),
    )
    op.create_index("ix_evidence_type", "evidence", ["type"])


def downgrade() -> None:
    op.drop_index("ix_evidence_type", table_name="evidence")
    op.drop_table("evidence")
