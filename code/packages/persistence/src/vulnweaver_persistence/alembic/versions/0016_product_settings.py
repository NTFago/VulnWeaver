"""Add installation-scoped non-secret product settings."""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0016_product_settings"
down_revision: str | None = "0015_pocs"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "product_settings",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("values", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "id = 'installation'",
            name=op.f("ck_product_settings_single_installation_settings"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_product_settings")),
    )


def downgrade() -> None:
    op.drop_table("product_settings")
