from __future__ import annotations

from typing import cast

from vulnweaver_contracts import (
    Artifact,
    ArtifactKind,
    ArtifactVersion,
    Job,
    JobKind,
    JobRequestedEvent,
    JobStatus,
    PermissionMode,
    Project,
    ResourceBudget,
    Task,
    TaskStatus,
    TaskStatusChangedEvent,
)

TIMESTAMP = "2026-09-07T08:00:00Z"


def budget() -> dict[str, int]:
    return {
        "max_model_tokens": 1000,
        "cpu_millis": 1000,
        "memory_bytes": 64 * 1024 * 1024,
        "disk_bytes": 128 * 1024 * 1024,
        "max_tool_concurrency": 1,
        "max_dynamic_runs": 0,
        "timeout_seconds": 60,
    }


def project(identifier: str = "project:t03") -> Project:
    return Project(
        schema_version="1.0.0",
        id=identifier,
        name="T03 integration project",
        input_scope=["local://authorized-sample"],
        permission_mode=PermissionMode.REQUEST_PERMISSION,
        exploit_validation_enabled=False,
        resource_budget=cast(ResourceBudget, budget()),
        created_at=TIMESTAMP,
    )


def artifact(
    identifier: str = "artifact:t03",
    *,
    project_id: str = "project:t03",
    current_version_id: str = "artifact-version:t03",
) -> Artifact:
    return Artifact(
        schema_version="1.0.0",
        id=identifier,
        project_id=project_id,
        kind=ArtifactKind.SOURCE_ARCHIVE,
        current_version_id=current_version_id,
        created_at=TIMESTAMP,
    )


def artifact_version(
    identifier: str = "artifact-version:t03",
    *,
    artifact_id: str = "artifact:t03",
    digest_character: str = "a",
) -> ArtifactVersion:
    return ArtifactVersion(
        schema_version="1.0.0",
        id=identifier,
        artifact_id=artifact_id,
        digest="sha256:" + digest_character * 64,
        object_ref=f"cas://sha256/{digest_character * 64}",
        generation_config={},
        created_at=TIMESTAMP,
    )


def task(
    identifier: str = "task:t03",
    *,
    project_id: str = "project:t03",
    artifact_version_ids: list[str] | None = None,
    idempotency_key: str = "task:t03-key",
) -> Task:
    return Task(
        schema_version="1.0.0",
        id=identifier,
        project_id=project_id,
        artifact_version_ids=artifact_version_ids or ["artifact-version:t03"],
        status=TaskStatus.CREATED,
        result=None,
        failure=None,
        idempotency_key=idempotency_key,
        resource_budget=cast(ResourceBudget, budget()),
        created_at=TIMESTAMP,
        updated_at=TIMESTAMP,
    )


def job(
    identifier: str = "job:t03",
    *,
    task_id: str = "task:t03",
    idempotency_key: str = "job:t03-key",
    kind: JobKind = JobKind.SOURCE_ANALYSIS,
) -> Job:
    return Job(
        schema_version="1.0.0",
        id=identifier,
        task_id=task_id,
        kind=kind,
        input_refs=["cas://sha256/" + "a" * 64],
        status=JobStatus.PENDING,
        idempotency_key=idempotency_key,
        resource_budget=cast(ResourceBudget, budget()),
        retry_policy={
            "max_attempts": 2,
            "backoff_seconds": 1.0,
            "retryable_failure_kinds": [],
        },
        attempt=0,
        lease=None,
        failure=None,
        created_at=TIMESTAMP,
        updated_at=TIMESTAMP,
    )


def job_event(value: Job, identifier: str = "event:t03") -> JobRequestedEvent:
    return JobRequestedEvent(
        schema_version="1.0.0",
        event_id=identifier,
        event_type="job.requested",
        aggregate_id=value["id"],
        sequence=0,
        occurred_at=TIMESTAMP,
        correlation_id=value["task_id"],
        causation_id=None,
        payload={
            "job_id": value["id"],
            "task_id": value["task_id"],
            "job_kind": value["kind"],
            "attempt": value["attempt"],
        },
    )


def task_event(
    *, identifier: str = "task-event:t03", sequence: int = 0
) -> TaskStatusChangedEvent:
    return TaskStatusChangedEvent(
        schema_version="1.0.0",
        event_id=identifier,
        event_type="task.status_changed",
        aggregate_id="task:t03",
        sequence=sequence,
        occurred_at=TIMESTAMP,
        correlation_id="task:t03",
        causation_id=None,
        payload={
            "task_id": "task:t03",
            "previous_status": TaskStatus.CREATED,
            "status": TaskStatus.VALIDATING,
            "result": None,
            "failure": None,
        },
    )
