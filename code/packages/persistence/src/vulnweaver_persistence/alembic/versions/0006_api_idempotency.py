"""Add T07 API idempotency and personal login records.

Revision ID: 0006_api_idempotency
Revises: 0005_job_retry_schedule
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006_api_idempotency"
down_revision: str | None = "0005_job_retry_schedule"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "api_requests",
        sa.Column("scope", sa.String(length=256), nullable=False),
        sa.Column("idempotency_key", sa.String(length=128), nullable=False),
        sa.Column("request_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("resource_type", sa.String(length=64), nullable=False),
        sa.Column("resource_id", sa.String(length=128), nullable=False),
        sa.Column("response_status", sa.Integer(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "response_status BETWEEN 200 AND 299",
            name=op.f("ck_api_requests_successful_response_status"),
        ),
        sa.PrimaryKeyConstraint("scope", "idempotency_key", name=op.f("pk_api_requests")),
    )
    op.create_table(
        "personal_accounts",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("username", sa.String(length=128), nullable=False),
        sa.Column("password_hash", sa.Text(), nullable=False),
        sa.Column(
            "must_change_password", sa.Boolean(), server_default=sa.text("false"), nullable=False
        ),
        sa.Column("password_version", sa.Integer(), server_default=sa.text("1"), nullable=False),
        sa.Column(
            "failed_login_attempts", sa.Integer(), server_default=sa.text("0"), nullable=False
        ),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "id = 'personal'", name=op.f("ck_personal_accounts_single_personal_account")
        ),
        sa.CheckConstraint(
            "password_version > 0", name=op.f("ck_personal_accounts_password_version_positive")
        ),
        sa.CheckConstraint(
            "failed_login_attempts >= 0",
            name=op.f("ck_personal_accounts_failed_login_attempts_non_negative"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_personal_accounts")),
        sa.UniqueConstraint("username", name=op.f("uq_personal_accounts_username")),
    )
    op.create_table(
        "personal_sessions",
        sa.Column("token_digest", sa.String(length=64), nullable=False),
        sa.Column("account_id", sa.String(length=32), nullable=False),
        sa.Column("csrf_digest", sa.String(length=64), nullable=False),
        sa.Column("password_version", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "password_version > 0", name=op.f("ck_personal_sessions_password_version_positive")
        ),
        sa.ForeignKeyConstraint(
            ["account_id"],
            ["personal_accounts.id"],
            name=op.f("fk_personal_sessions_account_id_personal_accounts"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("token_digest", name=op.f("pk_personal_sessions")),
    )
    op.create_index(
        op.f("ix_personal_sessions_expires_at"), "personal_sessions", ["expires_at"], unique=False
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_personal_sessions_expires_at"), table_name="personal_sessions")
    op.drop_table("personal_sessions")
    op.drop_table("personal_accounts")
    op.drop_table("api_requests")
