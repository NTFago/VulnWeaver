"""Align FindingEvidence contextual relation with the v1 contract."""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0013_finding_evidence_contextual"
down_revision: str | None = "0012_review_history"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_constraint(op.f("ck_finding_evidence_relation"), "finding_evidence", type_="check")
    op.execute("UPDATE finding_evidence SET relation = 'contextual' WHERE relation = 'context'")
    op.create_check_constraint(
        "relation",
        "finding_evidence",
        "relation IN ('supports', 'contradicts', 'contextual')",
    )


def downgrade() -> None:
    op.drop_constraint(op.f("ck_finding_evidence_relation"), "finding_evidence", type_="check")
    op.execute("UPDATE finding_evidence SET relation = 'context' WHERE relation = 'contextual'")
    op.create_check_constraint(
        "relation",
        "finding_evidence",
        "relation IN ('supports', 'contradicts', 'context')",
    )
