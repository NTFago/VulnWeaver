"""SQLAlchemy Core metadata for control-plane facts."""

from __future__ import annotations

from enum import StrEnum

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from vulnweaver_contracts import (
    ArtifactKind,
    JobKind,
    JobStatus,
    PermissionMode,
    TaskResult,
    TaskStatus,
)

NAMING_CONVENTION = {
    "ix": "ix_%(table_name)s_%(column_0_name)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}
metadata = MetaData(naming_convention=NAMING_CONVENTION)

IDENTIFIER = String(128)
SCHEMA_VERSION = String(16)
DIGEST = String(71)
TIMESTAMP = DateTime(timezone=True)


def _enum_constraint(column: str, enum_type: type[StrEnum], name: str) -> CheckConstraint:
    values = ", ".join(f"'{item.value}'" for item in enum_type)
    return CheckConstraint(f"{column} IN ({values})", name=name)


def _schema_constraint() -> CheckConstraint:
    return CheckConstraint("schema_version = '1.0.0'", name="schema_version_v1")


projects = Table(
    "projects",
    metadata,
    Column("id", IDENTIFIER, primary_key=True),
    Column("schema_version", SCHEMA_VERSION, nullable=False),
    Column("name", String(256), nullable=False),
    Column("input_scope", JSONB, nullable=False),
    Column("permission_mode", String(32), nullable=False),
    Column("exploit_validation_enabled", Boolean, nullable=False),
    Column("resource_budget", JSONB, nullable=False),
    Column("created_at", TIMESTAMP, nullable=False),
    _schema_constraint(),
    _enum_constraint("permission_mode", PermissionMode, "permission_mode"),
)

artifacts = Table(
    "artifacts",
    metadata,
    Column("id", IDENTIFIER, primary_key=True),
    Column("schema_version", SCHEMA_VERSION, nullable=False),
    Column(
        "project_id",
        IDENTIFIER,
        ForeignKey("projects.id", ondelete="RESTRICT"),
        nullable=False,
    ),
    Column("kind", String(32), nullable=False),
    Column(
        "current_version_id",
        IDENTIFIER,
        ForeignKey(
            "artifact_versions.id",
            name="fk_artifacts_current_version_id_artifact_versions",
            ondelete="RESTRICT",
            use_alter=True,
        ),
        nullable=True,
    ),
    Column("created_at", TIMESTAMP, nullable=False),
    _schema_constraint(),
    _enum_constraint("kind", ArtifactKind, "kind"),
)

artifact_versions = Table(
    "artifact_versions",
    metadata,
    Column("id", IDENTIFIER, primary_key=True),
    Column("schema_version", SCHEMA_VERSION, nullable=False),
    Column(
        "artifact_id",
        IDENTIFIER,
        ForeignKey("artifacts.id", ondelete="RESTRICT"),
        nullable=False,
    ),
    Column("digest", DIGEST, nullable=False),
    Column("object_ref", Text, nullable=False),
    Column(
        "parent_version_id",
        IDENTIFIER,
        ForeignKey("artifact_versions.id", ondelete="RESTRICT"),
        nullable=True,
    ),
    Column("produced_by", JSONB(none_as_null=True), nullable=True),
    Column("generation_config", JSONB, nullable=False),
    Column("created_at", TIMESTAMP, nullable=False),
    _schema_constraint(),
    CheckConstraint("digest ~ '^sha256:[0-9a-f]{64}$'", name="sha256_digest"),
    UniqueConstraint("artifact_id", "digest", name="uq_artifact_versions_artifact_digest"),
)

tasks = Table(
    "tasks",
    metadata,
    Column("id", IDENTIFIER, primary_key=True),
    Column("schema_version", SCHEMA_VERSION, nullable=False),
    Column(
        "project_id",
        IDENTIFIER,
        ForeignKey("projects.id", ondelete="RESTRICT"),
        nullable=False,
    ),
    Column("artifact_version_ids", JSONB, nullable=False),
    Column("status", String(32), nullable=False),
    Column("result", String(32), nullable=True),
    Column("idempotency_key", String(128), nullable=False),
    Column("request_fingerprint", String(64), nullable=False),
    Column("resource_budget", JSONB, nullable=False),
    Column("created_at", TIMESTAMP, nullable=False),
    Column("updated_at", TIMESTAMP, nullable=False),
    Column("state_version", Integer, nullable=False, server_default=text("0")),
    _schema_constraint(),
    _enum_constraint("status", TaskStatus, "status"),
    _enum_constraint("result", TaskResult, "result"),
    CheckConstraint(
        "(status = 'completed' AND result IS NOT NULL) OR "
        "(status <> 'completed' AND result IS NULL)",
        name="terminal_result",
    ),
    UniqueConstraint("project_id", "idempotency_key", name="uq_tasks_project_idempotency"),
)

jobs = Table(
    "jobs",
    metadata,
    Column("id", IDENTIFIER, primary_key=True),
    Column("schema_version", SCHEMA_VERSION, nullable=False),
    Column(
        "task_id",
        IDENTIFIER,
        ForeignKey("tasks.id", ondelete="RESTRICT"),
        nullable=False,
    ),
    Column("kind", String(32), nullable=False),
    Column("input_refs", JSONB, nullable=False),
    Column("status", String(32), nullable=False),
    Column("idempotency_key", String(128), nullable=False),
    Column("request_fingerprint", String(64), nullable=False),
    Column("resource_budget", JSONB, nullable=False),
    Column("retry_policy", JSONB, nullable=False),
    Column("attempt", Integer, nullable=False),
    Column("lease", JSONB(none_as_null=True), nullable=True),
    Column("failure", JSONB(none_as_null=True), nullable=True),
    Column("created_at", TIMESTAMP, nullable=False),
    Column("updated_at", TIMESTAMP, nullable=False),
    Column("state_version", Integer, nullable=False, server_default=text("0")),
    _schema_constraint(),
    _enum_constraint("kind", JobKind, "kind"),
    _enum_constraint("status", JobStatus, "status"),
    CheckConstraint("attempt >= 0", name="attempt_non_negative"),
    CheckConstraint(
        "(status = 'failed' AND failure IS NOT NULL) OR "
        "(status <> 'failed' AND failure IS NULL)",
        name="failure_matches_status",
    ),
    UniqueConstraint("task_id", "idempotency_key", name="uq_jobs_task_idempotency"),
)
Index("ix_jobs_task_status", jobs.c.task_id, jobs.c.status)

outbox_events = Table(
    "outbox_events",
    metadata,
    Column("id", IDENTIFIER, primary_key=True),
    Column("schema_version", SCHEMA_VERSION, nullable=False),
    Column("aggregate_type", String(64), nullable=False),
    Column("aggregate_id", IDENTIFIER, nullable=False),
    Column("event_type", String(128), nullable=False),
    Column("sequence", Integer, nullable=False),
    Column("occurred_at", TIMESTAMP, nullable=False),
    Column("correlation_id", IDENTIFIER, nullable=False),
    Column("causation_id", IDENTIFIER, nullable=True),
    Column("payload", JSONB, nullable=False),
    Column("available_at", TIMESTAMP, nullable=False),
    Column("published_at", TIMESTAMP, nullable=True),
    Column("dead_lettered_at", TIMESTAMP, nullable=True),
    Column("publish_attempts", Integer, nullable=False, server_default=text("0")),
    Column("last_error", JSONB(none_as_null=True), nullable=True),
    Column("dead_letter_reason", JSONB(none_as_null=True), nullable=True),
    Column("created_at", TIMESTAMP, nullable=False, server_default=text("now()")),
    _schema_constraint(),
    CheckConstraint("sequence >= 0", name="sequence_non_negative"),
    CheckConstraint("publish_attempts >= 0", name="publish_attempts_non_negative"),
    CheckConstraint(
        "NOT (published_at IS NOT NULL AND dead_lettered_at IS NOT NULL)",
        name="single_terminal_state",
    ),
    UniqueConstraint(
        "aggregate_type",
        "aggregate_id",
        "sequence",
        name="uq_outbox_events_aggregate_sequence",
    ),
)
Index(
    "ix_outbox_events_pending",
    outbox_events.c.available_at,
    outbox_events.c.created_at,
    postgresql_where=(
        outbox_events.c.published_at.is_(None)
        & outbox_events.c.dead_lettered_at.is_(None)
    ),
)

task_events = Table(
    "task_events",
    metadata,
    Column("id", IDENTIFIER, primary_key=True),
    Column("schema_version", SCHEMA_VERSION, nullable=False),
    Column(
        "task_id",
        IDENTIFIER,
        ForeignKey("tasks.id", ondelete="RESTRICT"),
        nullable=False,
    ),
    Column("event_type", String(128), nullable=False),
    Column("sequence", Integer, nullable=False),
    Column("occurred_at", TIMESTAMP, nullable=False),
    Column("correlation_id", IDENTIFIER, nullable=False),
    Column("causation_id", IDENTIFIER, nullable=True),
    Column("payload", JSONB, nullable=False),
    _schema_constraint(),
    CheckConstraint("sequence >= 0", name="sequence_non_negative"),
    UniqueConstraint("task_id", "sequence", name="uq_task_events_task_sequence"),
)
