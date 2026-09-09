"""SQLAlchemy Core metadata for control-plane facts."""

from __future__ import annotations

from enum import StrEnum

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    PrimaryKeyConstraint,
    String,
    Table,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from vulnweaver_contracts import (
    AnnotationTargetKind,
    ArtifactKind,
    EvidenceRelation,
    EvidenceStrength,
    EvidenceType,
    FindingCategory,
    FindingStatus,
    JobKind,
    JobStatus,
    PairEdgeType,
    PairNodeKind,
    PermissionMode,
    RunStatus,
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

pair_functions = Table(
    "pair_functions",
    metadata,
    Column("id", IDENTIFIER, primary_key=True),
    Column("schema_version", SCHEMA_VERSION, nullable=False),
    Column(
        "artifact_version_id",
        IDENTIFIER,
        ForeignKey("artifact_versions.id", ondelete="RESTRICT"),
        nullable=False,
    ),
    Column("name", String(2048), nullable=False),
    Column("symbol", String(2048), nullable=True),
    Column("language", String(128), nullable=False),
    Column("source_location", JSONB(none_as_null=True), nullable=True),
    Column("binary_location", JSONB(none_as_null=True), nullable=True),
    Column("signature", Text, nullable=True),
    Column("attributes", JSONB, nullable=False),
    Column("created_at", TIMESTAMP, nullable=False),
    _schema_constraint(),
    UniqueConstraint("artifact_version_id", "id", name="uq_pair_functions_version_id"),
)

pair_nodes = Table(
    "pair_nodes",
    metadata,
    Column("id", IDENTIFIER, primary_key=True),
    Column("schema_version", SCHEMA_VERSION, nullable=False),
    Column(
        "artifact_version_id",
        IDENTIFIER,
        ForeignKey("artifact_versions.id", ondelete="RESTRICT"),
        nullable=False,
    ),
    Column(
        "function_id",
        IDENTIFIER,
        ForeignKey("pair_functions.id", ondelete="RESTRICT"),
        nullable=True,
    ),
    Column("kind", String(32), nullable=False),
    Column("location", JSONB(none_as_null=True), nullable=True),
    Column("attributes", JSONB, nullable=False),
    Column("created_at", TIMESTAMP, nullable=False),
    _schema_constraint(),
    _enum_constraint("kind", PairNodeKind, "kind"),
    UniqueConstraint("artifact_version_id", "id", name="uq_pair_nodes_version_id"),
)

pair_edges = Table(
    "pair_edges",
    metadata,
    Column("id", IDENTIFIER, primary_key=True),
    Column("schema_version", SCHEMA_VERSION, nullable=False),
    Column(
        "artifact_version_id",
        IDENTIFIER,
        ForeignKey("artifact_versions.id", ondelete="RESTRICT"),
        nullable=False,
    ),
    Column(
        "source_node_id",
        IDENTIFIER,
        ForeignKey("pair_nodes.id", ondelete="RESTRICT"),
        nullable=False,
    ),
    Column(
        "target_node_id",
        IDENTIFIER,
        ForeignKey("pair_nodes.id", ondelete="RESTRICT"),
        nullable=False,
    ),
    Column("type", String(32), nullable=False),
    Column("scope", String(128), nullable=False),
    Column("confidence", Float(), nullable=False),
    Column("evidence_id", IDENTIFIER, nullable=True),
    Column("attributes", JSONB, nullable=False),
    Column("created_at", TIMESTAMP, nullable=False),
    _schema_constraint(),
    _enum_constraint("type", PairEdgeType, "type"),
    CheckConstraint("confidence >= 0 AND confidence <= 1", name="confidence_range"),
    UniqueConstraint(
        "artifact_version_id",
        "source_node_id",
        "target_node_id",
        "type",
        "scope",
        name="uq_pair_edges_identity",
    ),
)

pair_raw = Table(
    "pair_raw",
    metadata,
    Column("id", IDENTIFIER, primary_key=True),
    Column("schema_version", SCHEMA_VERSION, nullable=False),
    Column(
        "artifact_version_id",
        IDENTIFIER,
        ForeignKey("artifact_versions.id", ondelete="RESTRICT"),
        nullable=False,
    ),
    Column("tool", JSONB, nullable=False),
    Column("format", String(128), nullable=False),
    Column("object_ref", Text, nullable=False),
    Column("created_at", TIMESTAMP, nullable=False),
    _schema_constraint(),
    UniqueConstraint(
        "artifact_version_id", "tool", "format", "object_ref", name="uq_pair_raw_identity"
    ),
)

Index("ix_pair_functions_artifact_version_id", pair_functions.c.artifact_version_id)
Index("ix_pair_functions_source_path", pair_functions.c.source_location["path"].as_string())
Index("ix_pair_nodes_function_id", pair_nodes.c.function_id)
Index("ix_pair_nodes_artifact_version_id", pair_nodes.c.artifact_version_id)
Index("ix_pair_edges_source_node_id", pair_edges.c.source_node_id)
Index("ix_pair_edges_target_node_id", pair_edges.c.target_node_id)
Index("ix_pair_raw_artifact_version_id", pair_raw.c.artifact_version_id)

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

evidence = Table(
    "evidence",
    metadata,
    Column("id", IDENTIFIER, primary_key=True),
    Column("schema_version", SCHEMA_VERSION, nullable=False),
    Column("type", String(64), nullable=False),
    Column("strength", String(32), nullable=False),
    Column("artifact_ref", Text, nullable=False),
    Column("digest", DIGEST, nullable=False),
    Column("tool", JSONB(none_as_null=True), nullable=True),
    Column("input_ref", Text, nullable=False),
    Column("command_hash", DIGEST, nullable=True),
    Column("exit_code", Integer, nullable=True),
    Column("stdout_ref", Text, nullable=True),
    Column("stderr_ref", Text, nullable=True),
    Column("replay_recipe", JSONB, nullable=False),
    Column("created_at", TIMESTAMP, nullable=False),
    _schema_constraint(),
    _enum_constraint("type", EvidenceType, "type"),
    _enum_constraint("strength", EvidenceStrength, "strength"),
    CheckConstraint("digest ~ '^sha256:[0-9a-f]{64}$'", name="sha256_digest"),
    CheckConstraint(
        "command_hash IS NULL OR command_hash ~ '^sha256:[0-9a-f]{64}$'",
        name="command_sha256_digest",
    ),
)
Index("ix_evidence_type", evidence.c.type)

findings = Table(
    "findings",
    metadata,
    Column("id", IDENTIFIER, primary_key=True),
    Column("schema_version", SCHEMA_VERSION, nullable=False),
    Column("task_id", IDENTIFIER, ForeignKey("tasks.id", ondelete="RESTRICT"), nullable=False),
    Column("category", String(64), nullable=False),
    Column("cwe_id", String(128), nullable=False),
    Column("title", String(4096), nullable=False),
    Column("severity", String(32), nullable=False),
    Column("confidence", Float(), nullable=False),
    Column("location", JSONB, nullable=False),
    Column("dataflow", JSONB, nullable=False),
    Column("status", String(32), nullable=False),
    Column("evidence_ids", JSONB, nullable=False),
    Column("review_ids", JSONB, nullable=False),
    Column("poc_ids", JSONB, nullable=False),
    Column("fix_suggestion", Text, nullable=False),
    Column("created_at", TIMESTAMP, nullable=False),
    _schema_constraint(),
    _enum_constraint("category", FindingCategory, "category"),
    _enum_constraint("status", FindingStatus, "status"),
    CheckConstraint("confidence >= 0 AND confidence <= 1", name="confidence_range"),
)

finding_evidence = Table(
    "finding_evidence",
    metadata,
    Column("schema_version", SCHEMA_VERSION, nullable=False),
    Column(
        "finding_id", IDENTIFIER, ForeignKey("findings.id", ondelete="RESTRICT"), nullable=False
    ),
    Column(
        "evidence_id", IDENTIFIER, ForeignKey("evidence.id", ondelete="RESTRICT"), nullable=False
    ),
    Column("relation", String(32), nullable=False),
    Column("weight", Float(), nullable=False),
    Column("created_by", IDENTIFIER, nullable=False),
    Column("created_at", TIMESTAMP, nullable=False),
    _schema_constraint(),
    _enum_constraint("relation", EvidenceRelation, "relation"),
    CheckConstraint("weight >= 0 AND weight <= 1", name="weight_range"),
    PrimaryKeyConstraint("finding_id", "evidence_id", "relation", name="pk_finding_evidence"),
)

Index("ix_findings_task_id", findings.c.task_id)
Index("ix_findings_status", findings.c.status)
Index("ix_finding_evidence_evidence_id", finding_evidence.c.evidence_id)

reviews = Table(
    "reviews",
    metadata,
    Column("id", IDENTIFIER, primary_key=True),
    Column("schema_version", SCHEMA_VERSION, nullable=False),
    Column(
        "finding_id", IDENTIFIER, ForeignKey("findings.id", ondelete="RESTRICT"), nullable=False
    ),
    Column("outcome", String(32), nullable=False),
    Column("rationale", Text, nullable=False),
    Column("model", String(256), nullable=False),
    Column(
        "supersedes_review_id",
        IDENTIFIER,
        ForeignKey("reviews.id", ondelete="RESTRICT"),
        nullable=True,
    ),
    Column("created_at", TIMESTAMP, nullable=False),
    _schema_constraint(),
    _enum_constraint("outcome", FindingStatus, "outcome"),
)
Index("ix_reviews_finding_id", reviews.c.finding_id)

annotations = Table(
    "annotations",
    metadata,
    Column("id", IDENTIFIER, primary_key=True),
    Column("schema_version", SCHEMA_VERSION, nullable=False),
    Column("task_id", IDENTIFIER, ForeignKey("tasks.id", ondelete="RESTRICT"), nullable=False),
    Column("target_kind", String(32), nullable=False),
    Column("target_id", IDENTIFIER, nullable=False),
    Column("labels", JSONB, nullable=False),
    Column("note", Text, nullable=False),
    Column("severity_override", String(32), nullable=True),
    Column("author_id", IDENTIFIER, nullable=False),
    Column(
        "supersedes_annotation_id",
        IDENTIFIER,
        ForeignKey("annotations.id", ondelete="RESTRICT"),
        nullable=True,
        unique=True,
    ),
    Column("created_at", TIMESTAMP, nullable=False),
    _schema_constraint(),
    _enum_constraint("target_kind", AnnotationTargetKind, "target_kind"),
    CheckConstraint(
        "severity_override IS NULL OR severity_override IN "
        "('critical', 'high', 'medium', 'low', 'info')",
        name="severity_override",
    ),
)
Index("ix_annotations_task_id", annotations.c.task_id)
Index("ix_annotations_target", annotations.c.target_kind, annotations.c.target_id)

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
    Column("tool", JSONB(none_as_null=True), nullable=True),
    Column("arguments", JSONB(none_as_null=True), nullable=True),
    Column("input_refs", JSONB, nullable=False),
    Column("status", String(32), nullable=False),
    Column("idempotency_key", String(128), nullable=False),
    Column("request_fingerprint", String(64), nullable=False),
    Column("resource_budget", JSONB, nullable=False),
    Column("retry_policy", JSONB, nullable=False),
    Column("attempt", Integer, nullable=False),
    Column("retry_not_before", TIMESTAMP, nullable=True),
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
        "(status = 'failed' AND failure IS NOT NULL) OR (status <> 'failed' AND failure IS NULL)",
        name="failure_matches_status",
    ),
    UniqueConstraint("task_id", "idempotency_key", name="uq_jobs_task_idempotency"),
)
Index("ix_jobs_task_status", jobs.c.task_id, jobs.c.status)

job_results = Table(
    "job_results",
    metadata,
    Column(
        "job_id",
        IDENTIFIER,
        ForeignKey("jobs.id", ondelete="RESTRICT"),
        primary_key=True,
    ),
    Column("schema_version", SCHEMA_VERSION, nullable=False),
    Column("status", String(32), nullable=False),
    Column("produced_artifact_version_ids", JSONB, nullable=False),
    Column("evidence_ids", JSONB, nullable=False),
    Column("failure", JSONB(none_as_null=True), nullable=True),
    Column("result_fingerprint", String(64), nullable=False),
    Column("completed_at", TIMESTAMP, nullable=False, server_default=text("now()")),
    _schema_constraint(),
    _enum_constraint("status", JobStatus, "status"),
    CheckConstraint(
        "status IN ('succeeded', 'failed', 'cancelled')",
        name="terminal_status",
    ),
    CheckConstraint(
        "(status = 'failed' AND failure IS NOT NULL) OR (status <> 'failed' AND failure IS NULL)",
        name="failure_matches_status",
    ),
)

job_attempt_failures = Table(
    "job_attempt_failures",
    metadata,
    Column(
        "job_id",
        IDENTIFIER,
        ForeignKey("jobs.id", ondelete="RESTRICT"),
        primary_key=True,
    ),
    Column("attempt", Integer, primary_key=True),
    Column("schema_version", SCHEMA_VERSION, nullable=False),
    Column("owner", IDENTIFIER, nullable=False),
    Column("failure", JSONB, nullable=False),
    Column("failure_fingerprint", String(64), nullable=False),
    Column("recorded_at", TIMESTAMP, nullable=False, server_default=text("now()")),
    _schema_constraint(),
    CheckConstraint("attempt > 0", name="attempt_positive"),
)

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
        outbox_events.c.published_at.is_(None) & outbox_events.c.dead_lettered_at.is_(None)
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

agent_runs = Table(
    "agent_runs",
    metadata,
    Column("id", IDENTIFIER, primary_key=True),
    Column(
        "task_id",
        IDENTIFIER,
        ForeignKey("tasks.id", ondelete="RESTRICT"),
        nullable=False,
    ),
    Column("schema_version", SCHEMA_VERSION, nullable=False),
    Column("status", String(32), nullable=False),
    Column("model", String(256), nullable=False),
    Column("prompt_hash", DIGEST, nullable=False),
    Column("input_refs", JSONB, nullable=False),
    Column("decisions", JSONB, nullable=False),
    Column("token_usage", JSONB, nullable=False),
    Column("duration_ms", Integer, nullable=True),
    Column("result_refs", JSONB, nullable=True),
    Column("failure", JSONB(none_as_null=True), nullable=True),
    Column("run_fingerprint", String(64), nullable=False),
    Column("created_at", TIMESTAMP, nullable=False),
    Column("updated_at", TIMESTAMP, nullable=False),
    _schema_constraint(),
    _enum_constraint("status", RunStatus, "status"),
    CheckConstraint("prompt_hash ~ '^sha256:[0-9a-f]{64}$'", name="prompt_sha256_digest"),
    CheckConstraint("(status = 'failed') = (failure IS NOT NULL)", name="failure_matches_status"),
    CheckConstraint("duration_ms IS NULL OR duration_ms >= 0", name="duration_non_negative"),
    UniqueConstraint("task_id", "run_fingerprint", name="uq_agent_runs_task_fingerprint"),
)
Index("ix_agent_runs_task_created", agent_runs.c.task_id, agent_runs.c.created_at)

orchestration_checkpoints = Table(
    "orchestration_checkpoints",
    metadata,
    Column(
        "task_id",
        IDENTIFIER,
        ForeignKey("tasks.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column("sequence", Integer, primary_key=True),
    Column("node", IDENTIFIER, nullable=False),
    Column("state", JSONB, nullable=False),
    Column("state_fingerprint", String(64), nullable=False),
    Column("created_at", TIMESTAMP, nullable=False),
    CheckConstraint("sequence >= 0", name="sequence_non_negative"),
)
Index(
    "ix_orchestration_checkpoints_task_latest",
    orchestration_checkpoints.c.task_id,
    orchestration_checkpoints.c.sequence.desc(),
)


api_requests = Table(
    "api_requests",
    metadata,
    Column("scope", String(256), primary_key=True),
    Column("idempotency_key", String(128), primary_key=True),
    Column("request_fingerprint", String(64), nullable=False),
    Column("resource_type", String(64), nullable=False),
    Column("resource_id", IDENTIFIER, nullable=False),
    Column("response_status", Integer, nullable=False),
    Column("created_at", TIMESTAMP, nullable=False, server_default=text("now()")),
    CheckConstraint("response_status BETWEEN 200 AND 299", name="successful_response_status"),
)

personal_accounts = Table(
    "personal_accounts",
    metadata,
    Column("id", String(32), primary_key=True),
    Column("username", String(128), nullable=False, unique=True),
    Column("password_hash", Text, nullable=False),
    Column("must_change_password", Boolean, nullable=False, server_default=text("false")),
    Column("password_version", Integer, nullable=False, server_default=text("1")),
    Column("failed_login_attempts", Integer, nullable=False, server_default=text("0")),
    Column("locked_until", TIMESTAMP, nullable=True),
    Column("created_at", TIMESTAMP, nullable=False, server_default=text("now()")),
    Column("updated_at", TIMESTAMP, nullable=False, server_default=text("now()")),
    CheckConstraint("id = 'personal'", name="single_personal_account"),
    CheckConstraint("password_version > 0", name="password_version_positive"),
    CheckConstraint("failed_login_attempts >= 0", name="failed_login_attempts_non_negative"),
)

personal_sessions = Table(
    "personal_sessions",
    metadata,
    Column("token_digest", String(64), primary_key=True),
    Column(
        "account_id",
        String(32),
        ForeignKey("personal_accounts.id", ondelete="CASCADE"),
        nullable=False,
    ),
    Column("csrf_digest", String(64), nullable=False),
    Column("password_version", Integer, nullable=False),
    Column("expires_at", TIMESTAMP, nullable=False),
    Column("created_at", TIMESTAMP, nullable=False, server_default=text("now()")),
    CheckConstraint("password_version > 0", name="password_version_positive"),
)
Index("ix_personal_sessions_expires_at", personal_sessions.c.expires_at)
