"""Allow the fuzz Job kind in the jobs kind constraint.

T32 wired fuzz Jobs into the automatic pipeline, but migration 0017's kind
check predates it: every deployment built from migrations rejected fuzz Job
INSERTs with ``ck_jobs_kind`` while metadata-created test tables accepted
them. Adds ``fuzz`` to the allowed kinds.

Revision ID: 0020_fuzz_job_kind
Revises: 0019_task_failure
Create Date: 2026-09-11
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
            "'binary_analysis', 'review', 'proof', 'exploit', 'fuzz', 'report')",
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
