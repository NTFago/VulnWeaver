"""Allow the poc_verification_result evidence type."""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0021_poc_verification_evidence"
down_revision: str | None = "0020_fuzz_job_kind"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_EVIDENCE_TYPES = (
    "'model_explanation', 'tool_output', 'code_snippet', 'dataflow_path', "
    "'crash_record', 'reproduction_result', 'poc_verification_result', "
    "'exploit_record', 'review_conclusion', 'human_confirmation'"
)

# Raw SQL because the metadata naming convention would otherwise wrap the
# constraint name a second time (ck_evidence_ck_evidence_type).
_UPGRADE_SQL = (
    f"ALTER TABLE evidence DROP CONSTRAINT ck_evidence_type; "
    f"ALTER TABLE evidence ADD CONSTRAINT ck_evidence_type "
    f"CHECK (type IN ({_EVIDENCE_TYPES})) NOT VALID"
)
_DOWNGRADE_TYPES = _EVIDENCE_TYPES.replace("'poc_verification_result', ", "")
_DOWNGRADE_SQL = (
    f"ALTER TABLE evidence DROP CONSTRAINT ck_evidence_type; "
    f"ALTER TABLE evidence ADD CONSTRAINT ck_evidence_type "
    f"CHECK (type IN ({_DOWNGRADE_TYPES})) NOT VALID"
)


def upgrade() -> None:
    op.execute(_UPGRADE_SQL)


def downgrade() -> None:
    op.execute(_DOWNGRADE_SQL)
