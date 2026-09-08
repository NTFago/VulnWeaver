"""Add AgentRun and durable orchestration checkpoint facts."""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0007_agent_runs_checkpoints"
down_revision: str | None = "0006_api_idempotency"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "agent_runs",
        sa.Column("id", sa.String(length=128), nullable=False),
        sa.Column("task_id", sa.String(length=128), nullable=False),
        sa.Column("schema_version", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("model", sa.String(length=256), nullable=False),
        sa.Column("prompt_hash", sa.String(length=71), nullable=False),
        sa.Column("input_refs", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("decisions", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("token_usage", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("result_refs", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("failure", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("run_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "schema_version = '1.0.0'",
            name=op.f("ck_agent_runs_schema_version_v1"),
        ),
        sa.CheckConstraint(
            "status IN ('created', 'running', 'succeeded', 'failed', 'cancelled')",
            name=op.f("ck_agent_runs_status"),
        ),
        sa.CheckConstraint(
            "prompt_hash ~ '^sha256:[0-9a-f]{64}$'",
            name=op.f("ck_agent_runs_prompt_sha256_digest"),
        ),
        sa.CheckConstraint(
            "(status = 'failed') = (failure IS NOT NULL)",
            name=op.f("ck_agent_runs_failure_matches_status"),
        ),
        sa.CheckConstraint(
            "duration_ms IS NULL OR duration_ms >= 0",
            name=op.f("ck_agent_runs_duration_non_negative"),
        ),
        sa.ForeignKeyConstraint(
            ["task_id"], ["tasks.id"], name=op.f("fk_agent_runs_task_id_tasks"), ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_agent_runs")),
        sa.UniqueConstraint(
            "task_id", "run_fingerprint", name=op.f("uq_agent_runs_task_fingerprint")
        ),
    )
    op.create_index(
        op.f("ix_agent_runs_task_created"),
        "agent_runs",
        ["task_id", "created_at"],
        unique=False,
    )
    op.create_table(
        "orchestration_checkpoints",
        sa.Column("task_id", sa.String(length=128), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("node", sa.String(length=128), nullable=False),
        sa.Column("state", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("state_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "sequence >= 0",
            name=op.f("ck_orchestration_checkpoints_sequence_non_negative"),
        ),
        sa.ForeignKeyConstraint(
            ["task_id"],
            ["tasks.id"],
            name=op.f("fk_orchestration_checkpoints_task_id_tasks"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "task_id", "sequence", name=op.f("pk_orchestration_checkpoints")
        ),
    )
    op.create_index(
        op.f("ix_orchestration_checkpoints_task_latest"),
        "orchestration_checkpoints",
        ["task_id", sa.text("sequence DESC")],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_orchestration_checkpoints_task_latest"),
        table_name="orchestration_checkpoints",
    )
    op.drop_table("orchestration_checkpoints")
    op.drop_index(op.f("ix_agent_runs_task_created"), table_name="agent_runs")
    op.drop_table("agent_runs")
