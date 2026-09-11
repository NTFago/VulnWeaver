"""Allow the fuzz Job kind in the jobs kind constraint.

The fuzz Job kind exists in the v1 contract and in the models metadata
(derived from the JobKind enum) since automatic fuzz dispatch landed, but the
check constraint was last rewritten by 0017 before that, so scheduling a fuzz
Job violated ck_jobs_kind and wedged the pipeline settlement.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0020_fuzz_job_kind"
down_revision: str | None = "0019_task_failure"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("jobs") as batch:
        batch.drop_constraint(op.f("ck_jobs_kind"), type_="check")
        batch.create_check_constraint(
            op.f("ck_jobs_kind"),
            "kind IN ('validate', 'import', 'source_analysis', 'semantic_audit', "
            "'binary_analysis', 'review', 'fuzz', 'proof', 'exploit', 'report')",
        )


def downgrade() -> None:
    op.execute("DELETE FROM jobs WHERE kind = 'fuzz'")
    with op.batch_alter_table("jobs") as batch:
        batch.drop_constraint(op.f("ck_jobs_kind"), type_="check")
        batch.create_check_constraint(
            op.f("ck_jobs_kind"),
            "kind IN ('validate', 'import', 'source_analysis', 'semantic_audit', "
            "'binary_analysis', 'review', 'proof', 'exploit', 'report')",
        )
