"""Widen pocs.result for the not_exploitable_under_environment value.

The PocResult contract has always allowed ``not_exploitable_under_environment``
(33 characters) but the column was varchar(32), so the value could never be
persisted. The independent-verifier mapping now produces it, so widen the
column to varchar(64). The enum CHECK constraint is unchanged.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0024_poc_result_width"
down_revision: str | None = "0023_verification_evidence"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("ALTER TABLE pocs ALTER COLUMN result TYPE VARCHAR(64)")


def downgrade() -> None:
    # Narrowing would fail while any 33+ character value exists.
    op.execute(
        "DELETE FROM pocs WHERE length(result) > 32;"
        "ALTER TABLE pocs ALTER COLUMN result TYPE VARCHAR(32)"
    )
