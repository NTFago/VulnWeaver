"""Create immutable Finding Review history."""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0012_review_history"
down_revision: str | None = "0011_finding_candidates"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "reviews",
        sa.Column("id", sa.String(128), nullable=False),
        sa.Column("schema_version", sa.String(16), nullable=False),
        sa.Column("finding_id", sa.String(128), nullable=False),
        sa.Column("outcome", sa.String(32), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("model", sa.String(256), nullable=False),
        sa.Column("supersedes_review_id", sa.String(128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("schema_version = '1.0.0'", name="schema_version_v1"),
        sa.CheckConstraint(
            "outcome IN ('candidate', 'confirmed', 'false_positive', 'disputed', 'unverifiable')",
            name="outcome",
        ),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["supersedes_review_id"], ["reviews.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id", name="pk_reviews"),
    )
    op.create_index("ix_reviews_finding_id", "reviews", ["finding_id"])


def downgrade() -> None:
    op.drop_index("ix_reviews_finding_id", table_name="reviews")
    op.drop_table("reviews")
