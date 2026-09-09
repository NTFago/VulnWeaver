"""Persist immutable proof-of-concept results."""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0015_pocs"
down_revision: str | None = "0014_annotations"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "pocs",
        sa.Column("schema_version", sa.String(length=16), nullable=False),
        sa.Column("id", sa.String(length=128), nullable=False),
        sa.Column("finding_id", sa.String(length=128), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("result", sa.String(length=32), nullable=True),
        sa.Column("script_ref", sa.Text(), nullable=False),
        sa.Column("run_log_ref", sa.Text(), nullable=True),
        sa.Column("image_digest", sa.String(length=71), nullable=False),
        sa.Column("permission_mode", sa.String(length=32), nullable=False),
        sa.Column("resource_budget", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("schema_version = '1.0.0'", name=op.f("ck_pocs_schema_version_v1")),
        sa.CheckConstraint("kind IN ('exploit', 'reproduction')", name=op.f("ck_pocs_kind")),
        sa.CheckConstraint(
            "status IN ('pending', 'running', 'completed', 'failed', 'cancelled')",
            name=op.f("ck_pocs_status"),
        ),
        sa.CheckConstraint(
            "result IS NULL OR result IN ("
            "'exploitable', 'not_exploitable', 'inconclusive', "
            "'timeout', 'policy_denied', 'tool_error', 'environment_error')",
            name=op.f("ck_pocs_result"),
        ),
        sa.CheckConstraint(
            "permission_mode IN ('read_only', 'workspace_write', 'network_isolated')",
            name=op.f("ck_pocs_permission_mode"),
        ),
        sa.CheckConstraint(
            "image_digest ~ '^sha256:[0-9a-f]{64}$'", name=op.f("ck_pocs_sha256_digest")
        ),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["findings.id"],
            name=op.f("fk_pocs_finding_id_findings"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_pocs")),
    )
    op.create_index(op.f("ix_pocs_finding_id"), "pocs", ["finding_id"])


def downgrade() -> None:
    op.drop_index(op.f("ix_pocs_finding_id"), table_name="pocs")
    op.drop_table("pocs")
