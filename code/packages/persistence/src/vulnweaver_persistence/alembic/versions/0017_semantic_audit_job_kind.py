"""Allow the semantic_audit Job kind in the jobs kind constraint."""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0017_semantic_audit_job_kind"
down_revision: str | None = "0016_product_settings"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("jobs") as batch:
        batch.drop_constraint(op.f("ck_jobs_kind"), type_="check")
        batch.create_check_constraint(
            op.f("ck_jobs_kind"),
            "kind IN ('validate', 'import', 'source_analysis', 'semantic_audit', "
            "'binary_analysis', 'review', 'proof', 'exploit', 'report')",
        )


def downgrade() -> None:
    op.execute("DELETE FROM jobs WHERE kind = 'semantic_audit'")
    with op.batch_alter_table("jobs") as batch:
        batch.drop_constraint(op.f("ck_jobs_kind"), type_="check")
        batch.create_check_constraint(
            op.f("ck_jobs_kind"),
            "kind IN ('validate', 'import', 'source_analysis', 'binary_analysis', "
            "'review', 'proof', 'exploit', 'report')",
        )
