"""Create the control-plane core tables.

Revision ID: 0001_control_plane_core
Revises: None
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001_control_plane_core"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "projects",
        sa.Column("id", sa.String(length=128), nullable=False),
        sa.Column("schema_version", sa.String(length=16), nullable=False),
        sa.Column("name", sa.String(length=256), nullable=False),
        sa.Column("input_scope", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("permission_mode", sa.String(length=32), nullable=False),
        sa.Column("exploit_validation_enabled", sa.Boolean(), nullable=False),
        sa.Column("resource_budget", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "permission_mode IN ('request_permission', 'full_access')",
            name=op.f("ck_projects_permission_mode"),
        ),
        sa.CheckConstraint(
            "schema_version = '1.0.0'", name=op.f("ck_projects_schema_version_v1")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_projects")),
    )
    op.create_table(
        "artifacts",
        sa.Column("id", sa.String(length=128), nullable=False),
        sa.Column("schema_version", sa.String(length=16), nullable=False),
        sa.Column("project_id", sa.String(length=128), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("current_version_id", sa.String(length=128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "kind IN ('source_archive', 'source_repository', 'elf', 'pe', 'derived')",
            name=op.f("ck_artifacts_kind"),
        ),
        sa.CheckConstraint(
            "schema_version = '1.0.0'", name=op.f("ck_artifacts_schema_version_v1")
        ),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["projects.id"],
            name=op.f("fk_artifacts_project_id_projects"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_artifacts")),
    )
    op.create_table(
        "artifact_versions",
        sa.Column("id", sa.String(length=128), nullable=False),
        sa.Column("schema_version", sa.String(length=16), nullable=False),
        sa.Column("artifact_id", sa.String(length=128), nullable=False),
        sa.Column("digest", sa.String(length=71), nullable=False),
        sa.Column("object_ref", sa.Text(), nullable=False),
        sa.Column("parent_version_id", sa.String(length=128), nullable=True),
        sa.Column("produced_by", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("generation_config", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "digest ~ '^sha256:[0-9a-f]{64}$'",
            name=op.f("ck_artifact_versions_sha256_digest"),
        ),
        sa.CheckConstraint(
            "schema_version = '1.0.0'",
            name=op.f("ck_artifact_versions_schema_version_v1"),
        ),
        sa.ForeignKeyConstraint(
            ["artifact_id"],
            ["artifacts.id"],
            name=op.f("fk_artifact_versions_artifact_id_artifacts"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["parent_version_id"],
            ["artifact_versions.id"],
            name=op.f("fk_artifact_versions_parent_version_id_artifact_versions"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_artifact_versions")),
        sa.UniqueConstraint(
            "artifact_id", "digest", name="uq_artifact_versions_artifact_digest"
        ),
    )
    op.create_foreign_key(
        "fk_artifacts_current_version_id_artifact_versions",
        "artifacts",
        "artifact_versions",
        ["current_version_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.create_table(
        "tasks",
        sa.Column("id", sa.String(length=128), nullable=False),
        sa.Column("schema_version", sa.String(length=16), nullable=False),
        sa.Column("project_id", sa.String(length=128), nullable=False),
        sa.Column("artifact_version_ids", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("result", sa.String(length=32), nullable=True),
        sa.Column("idempotency_key", sa.String(length=128), nullable=False),
        sa.Column("request_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("resource_budget", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("state_version", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.CheckConstraint(
            "result IN ('success', 'partial', 'no_findings')",
            name=op.f("ck_tasks_result"),
        ),
        sa.CheckConstraint(
            "schema_version = '1.0.0'", name=op.f("ck_tasks_schema_version_v1")
        ),
        sa.CheckConstraint(
            "status IN ('created', 'validating', 'analyzing', 'reviewing', "
            "'verifying', 'exploiting', 'reporting', 'completed', 'failed', 'cancelled')",
            name=op.f("ck_tasks_status"),
        ),
        sa.CheckConstraint(
            "(status = 'completed' AND result IS NOT NULL) OR "
            "(status <> 'completed' AND result IS NULL)",
            name=op.f("ck_tasks_terminal_result"),
        ),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["projects.id"],
            name=op.f("fk_tasks_project_id_projects"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_tasks")),
        sa.UniqueConstraint(
            "project_id", "idempotency_key", name="uq_tasks_project_idempotency"
        ),
    )
    op.create_table(
        "jobs",
        sa.Column("id", sa.String(length=128), nullable=False),
        sa.Column("schema_version", sa.String(length=16), nullable=False),
        sa.Column("task_id", sa.String(length=128), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("input_refs", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("idempotency_key", sa.String(length=128), nullable=False),
        sa.Column("request_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("resource_budget", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("retry_policy", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("attempt", sa.Integer(), nullable=False),
        sa.Column("lease", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("failure", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("state_version", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.CheckConstraint("attempt >= 0", name=op.f("ck_jobs_attempt_non_negative")),
        sa.CheckConstraint(
            "(status = 'failed' AND failure IS NOT NULL) OR "
            "(status <> 'failed' AND failure IS NULL)",
            name=op.f("ck_jobs_failure_matches_status"),
        ),
        sa.CheckConstraint(
            "kind IN ('validate', 'import', 'source_analysis', 'binary_analysis', "
            "'review', 'proof', 'exploit', 'report')",
            name=op.f("ck_jobs_kind"),
        ),
        sa.CheckConstraint(
            "schema_version = '1.0.0'", name=op.f("ck_jobs_schema_version_v1")
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'queued', 'running', 'waiting_permission', "
            "'succeeded', 'failed', 'cancelled')",
            name=op.f("ck_jobs_status"),
        ),
        sa.ForeignKeyConstraint(
            ["task_id"], ["tasks.id"], name=op.f("fk_jobs_task_id_tasks"), ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_jobs")),
        sa.UniqueConstraint("task_id", "idempotency_key", name="uq_jobs_task_idempotency"),
    )
    op.create_index("ix_jobs_task_status", "jobs", ["task_id", "status"], unique=False)
    op.create_table(
        "outbox_events",
        sa.Column("id", sa.String(length=128), nullable=False),
        sa.Column("schema_version", sa.String(length=16), nullable=False),
        sa.Column("aggregate_type", sa.String(length=64), nullable=False),
        sa.Column("aggregate_id", sa.String(length=128), nullable=False),
        sa.Column("event_type", sa.String(length=128), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("correlation_id", sa.String(length=128), nullable=False),
        sa.Column("causation_id", sa.String(length=128), nullable=True),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("publish_attempts", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("last_error", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "publish_attempts >= 0", name=op.f("ck_outbox_events_publish_attempts_non_negative")
        ),
        sa.CheckConstraint(
            "schema_version = '1.0.0'", name=op.f("ck_outbox_events_schema_version_v1")
        ),
        sa.CheckConstraint(
            "sequence >= 0", name=op.f("ck_outbox_events_sequence_non_negative")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_outbox_events")),
        sa.UniqueConstraint(
            "aggregate_type",
            "aggregate_id",
            "sequence",
            name="uq_outbox_events_aggregate_sequence",
        ),
    )
    op.create_index(
        "ix_outbox_events_pending",
        "outbox_events",
        ["available_at", "created_at"],
        unique=False,
        postgresql_where=sa.text("published_at IS NULL"),
    )
    op.create_table(
        "task_events",
        sa.Column("id", sa.String(length=128), nullable=False),
        sa.Column("schema_version", sa.String(length=16), nullable=False),
        sa.Column("task_id", sa.String(length=128), nullable=False),
        sa.Column("event_type", sa.String(length=128), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("correlation_id", sa.String(length=128), nullable=False),
        sa.Column("causation_id", sa.String(length=128), nullable=True),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.CheckConstraint(
            "schema_version = '1.0.0'", name=op.f("ck_task_events_schema_version_v1")
        ),
        sa.CheckConstraint(
            "sequence >= 0", name=op.f("ck_task_events_sequence_non_negative")
        ),
        sa.ForeignKeyConstraint(
            ["task_id"],
            ["tasks.id"],
            name=op.f("fk_task_events_task_id_tasks"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_task_events")),
        sa.UniqueConstraint("task_id", "sequence", name="uq_task_events_task_sequence"),
    )


def downgrade() -> None:
    op.drop_table("task_events")
    op.drop_index("ix_outbox_events_pending", table_name="outbox_events")
    op.drop_table("outbox_events")
    op.drop_index("ix_jobs_task_status", table_name="jobs")
    op.drop_table("jobs")
    op.drop_table("tasks")
    op.drop_constraint(
        "fk_artifacts_current_version_id_artifact_versions",
        "artifacts",
        type_="foreignkey",
    )
    op.drop_table("artifact_versions")
    op.drop_table("artifacts")
    op.drop_table("projects")
