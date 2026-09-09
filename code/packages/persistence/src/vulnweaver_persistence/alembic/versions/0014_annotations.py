"""Add append-only function and Finding annotations."""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0014_annotations"
down_revision: str | None = "0013_finding_evidence_contextual"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "annotations",
        sa.Column("id", sa.String(length=128), nullable=False),
        sa.Column("schema_version", sa.String(length=16), nullable=False),
        sa.Column("task_id", sa.String(length=128), nullable=False),
        sa.Column("target_kind", sa.String(length=32), nullable=False),
        sa.Column("target_id", sa.String(length=128), nullable=False),
        sa.Column("labels", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("note", sa.Text(), nullable=False),
        sa.Column("severity_override", sa.String(length=32), nullable=True),
        sa.Column("author_id", sa.String(length=128), nullable=False),
        sa.Column("supersedes_annotation_id", sa.String(length=128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "schema_version = '1.0.0'",
            name=op.f("ck_annotations_schema_version_v1"),
        ),
        sa.CheckConstraint(
            "target_kind IN ('function', 'finding')",
            name=op.f("ck_annotations_target_kind"),
        ),
        sa.CheckConstraint(
            "severity_override IS NULL OR severity_override IN "
            "('critical', 'high', 'medium', 'low', 'info')",
            name=op.f("ck_annotations_severity_override"),
        ),
        sa.ForeignKeyConstraint(
            ["supersedes_annotation_id"],
            ["annotations.id"],
            name=op.f("fk_annotations_supersedes_annotation_id_annotations"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["task_id"],
            ["tasks.id"],
            name=op.f("fk_annotations_task_id_tasks"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_annotations")),
        sa.UniqueConstraint(
            "supersedes_annotation_id",
            name=op.f("uq_annotations_supersedes_annotation_id"),
        ),
    )
    op.create_index(op.f("ix_annotations_task_id"), "annotations", ["task_id"])
    op.create_index(
        "ix_annotations_target", "annotations", ["target_kind", "target_id"]
    )


def downgrade() -> None:
    op.drop_index("ix_annotations_target", table_name="annotations")
    op.drop_index(op.f("ix_annotations_task_id"), table_name="annotations")
    op.drop_table("annotations")
