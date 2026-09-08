"""Create candidate Finding and FindingEvidence relations."""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0011_finding_candidates"
down_revision: str | None = "0010_evidence"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "findings",
        sa.Column("id", sa.String(128), nullable=False),
        sa.Column("schema_version", sa.String(16), nullable=False),
        sa.Column("task_id", sa.String(128), nullable=False),
        sa.Column("category", sa.String(64), nullable=False),
        sa.Column("cwe_id", sa.String(128), nullable=False),
        sa.Column("title", sa.String(4096), nullable=False),
        sa.Column("severity", sa.String(32), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("location", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("dataflow", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("evidence_ids", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("review_ids", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("poc_ids", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("fix_suggestion", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("schema_version = '1.0.0'", name="schema_version_v1"),
        sa.CheckConstraint(
            "category IN ('memory_corruption', 'injection', "
            "'auth_or_business_logic', 'static_only')",
            name="category",
        ),
        sa.CheckConstraint(
            "status IN ('candidate', 'confirmed', 'false_positive', 'disputed', 'unverifiable')",
            name="status",
        ),
        sa.CheckConstraint("confidence >= 0 AND confidence <= 1", name="confidence_range"),
        sa.ForeignKeyConstraint(["task_id"], ["tasks.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id", name="pk_findings"),
    )
    op.create_index("ix_findings_task_id", "findings", ["task_id"])
    op.create_index("ix_findings_status", "findings", ["status"])

    op.create_table(
        "finding_evidence",
        sa.Column("schema_version", sa.String(16), nullable=False),
        sa.Column("finding_id", sa.String(128), nullable=False),
        sa.Column("evidence_id", sa.String(128), nullable=False),
        sa.Column("relation", sa.String(32), nullable=False),
        sa.Column("weight", sa.Float(), nullable=False),
        sa.Column("created_by", sa.String(128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("schema_version = '1.0.0'", name="schema_version_v1"),
        sa.CheckConstraint("relation IN ('supports', 'contradicts', 'context')", name="relation"),
        sa.CheckConstraint("weight >= 0 AND weight <= 1", name="weight_range"),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["evidence_id"], ["evidence.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint(
            "finding_id", "evidence_id", "relation", name="pk_finding_evidence"
        ),
    )
    op.create_index("ix_finding_evidence_evidence_id", "finding_evidence", ["evidence_id"])


def downgrade() -> None:
    op.drop_index("ix_finding_evidence_evidence_id", table_name="finding_evidence")
    op.drop_table("finding_evidence")
    op.drop_index("ix_findings_status", table_name="findings")
    op.drop_index("ix_findings_task_id", table_name="findings")
    op.drop_table("findings")
