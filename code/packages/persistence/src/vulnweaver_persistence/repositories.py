"""Transaction-scoped repositories for control-plane facts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import cast

from sqlalchemy import RowMapping, func, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncConnection
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
    QueueEvent,
    Task,
    TaskResult,
    TaskStatus,
    validate_contract,
)

from vulnweaver_persistence.errors import (
    EntityConflict,
    EntityNotFound,
    IdempotencyConflict,
    PersistenceInvariantError,
)
from vulnweaver_persistence.fingerprints import request_fingerprint
from vulnweaver_persistence.models import (
    artifact_versions,
    artifacts,
    jobs,
    outbox_events,
    projects,
    task_events,
    tasks,
)


@dataclass(frozen=True, slots=True)
class CreateResult[T]:
    value: T
    created: bool


@dataclass(frozen=True, slots=True)
class JobEnqueueResult:
    job: Job
    event: JobRequestedEvent
    created: bool


@dataclass(frozen=True, slots=True)
class OutboxMessage:
    event: QueueEvent
    publish_attempts: int
    available_at: datetime


class ProjectRepository:
    def __init__(self, connection: AsyncConnection) -> None:
        self._connection = connection

    async def add(self, project: Project) -> Project:
        validate_contract("Project", project)
        try:
            await self._connection.execute(insert(projects).values(_project_values(project)))
        except IntegrityError as error:
            raise EntityConflict(
                "project identifier already exists", details={"project_id": project["id"]}
            ) from error
        return project

    async def get(self, project_id: str) -> Project:
        row = (
            await self._connection.execute(select(projects).where(projects.c.id == project_id))
        ).mappings().one_or_none()
        if row is None:
            raise EntityNotFound("project not found", details={"project_id": project_id})
        return _project_from_row(row)


class ArtifactRepository:
    def __init__(self, connection: AsyncConnection) -> None:
        self._connection = connection

    async def add(self, artifact: Artifact) -> Artifact:
        validate_contract("Artifact", artifact)
        values = _artifact_values(artifact)
        # The first version is registered separately in the same transaction.
        values["current_version_id"] = None
        try:
            await self._connection.execute(insert(artifacts).values(values))
        except IntegrityError as error:
            raise EntityConflict(
                "artifact identifier already exists", details={"artifact_id": artifact["id"]}
            ) from error
        return artifact

    async def get(self, artifact_id: str) -> Artifact:
        row = (
            await self._connection.execute(
                select(artifacts).where(artifacts.c.id == artifact_id)
            )
        ).mappings().one_or_none()
        if row is None:
            raise EntityNotFound(
                "artifact not found", details={"artifact_id": artifact_id}
            )
        return _artifact_from_row(row)

    async def get_version(self, version_id: str) -> ArtifactVersion:
        row = (
            await self._connection.execute(
                select(artifact_versions).where(artifact_versions.c.id == version_id)
            )
        ).mappings().one_or_none()
        if row is None:
            raise EntityNotFound(
                "artifact version not found",
                details={"artifact_version_id": version_id},
            )
        return _artifact_version_from_row(row)

    async def add_version(self, version: ArtifactVersion) -> CreateResult[ArtifactVersion]:
        validate_contract("ArtifactVersion", version)
        statement = (
            insert(artifact_versions)
            .values(_artifact_version_values(version))
            .on_conflict_do_nothing(constraint="uq_artifact_versions_artifact_digest")
            .returning(artifact_versions.c.id)
        )
        try:
            inserted_id = (await self._connection.execute(statement)).scalar_one_or_none()
        except IntegrityError as error:
            raise EntityConflict(
                "artifact version conflicts with an existing identifier",
                details={"artifact_version_id": version["id"]},
            ) from error

        if inserted_id is None:
            row = (
                await self._connection.execute(
                    select(artifact_versions).where(
                        artifact_versions.c.artifact_id == version["artifact_id"],
                        artifact_versions.c.digest == version["digest"],
                    )
                )
            ).mappings().one()
            stored = _artifact_version_from_row(row)
            created = False
        else:
            stored = version
            created = True

        await self._connection.execute(
            update(artifacts)
            .where(artifacts.c.id == version["artifact_id"])
            .values(current_version_id=stored["id"])
        )
        return CreateResult(stored, created)


class TaskRepository:
    def __init__(self, connection: AsyncConnection) -> None:
        self._connection = connection

    async def create(self, task: Task) -> CreateResult[Task]:
        validate_contract("Task", task)
        fingerprint = _task_fingerprint(task)
        statement = (
            insert(tasks)
            .values(_task_values(task, fingerprint))
            .on_conflict_do_nothing(constraint="uq_tasks_project_idempotency")
            .returning(tasks.c.id)
        )
        try:
            inserted_id = (await self._connection.execute(statement)).scalar_one_or_none()
        except IntegrityError as error:
            raise EntityConflict(
                "task identifier already exists", details={"task_id": task["id"]}
            ) from error
        if inserted_id is not None:
            return CreateResult(task, True)

        row = (
            await self._connection.execute(
                select(tasks).where(
                    tasks.c.project_id == task["project_id"],
                    tasks.c.idempotency_key == task["idempotency_key"],
                )
            )
        ).mappings().one()
        if row["request_fingerprint"] != fingerprint:
            raise IdempotencyConflict(
                "idempotency key was already used for a different task request",
                details={
                    "project_id": task["project_id"],
                    "idempotency_key": task["idempotency_key"],
                },
            )
        return CreateResult(_task_from_row(row), False)

    async def get(self, task_id: str) -> Task:
        row = (
            await self._connection.execute(select(tasks).where(tasks.c.id == task_id))
        ).mappings().one_or_none()
        if row is None:
            raise EntityNotFound("task not found", details={"task_id": task_id})
        return _task_from_row(row)


class JobRepository:
    def __init__(self, connection: AsyncConnection) -> None:
        self._connection = connection

    async def enqueue_with_outbox(
        self, job: Job, event: JobRequestedEvent
    ) -> JobEnqueueResult:
        """Create a Job and its dispatch event in the caller's single transaction."""

        validate_contract("Job", job)
        validate_contract("JobRequestedEvent", event)
        _ensure_event_matches_job(job, event)
        fingerprint = _job_fingerprint(job)
        statement = (
            insert(jobs)
            .values(_job_values(job, fingerprint))
            .on_conflict_do_nothing(constraint="uq_jobs_task_idempotency")
            .returning(jobs.c.id)
        )
        try:
            inserted_id = (await self._connection.execute(statement)).scalar_one_or_none()
        except IntegrityError as error:
            raise EntityConflict(
                "job identifier already exists", details={"job_id": job["id"]}
            ) from error

        if inserted_id is None:
            return await self._resolve_idempotent_retry(job, fingerprint)

        try:
            await self._connection.execute(insert(outbox_events).values(_outbox_values(event)))
        except IntegrityError as error:
            raise EntityConflict(
                "outbox event conflicts with an existing event",
                details={"event_id": event["event_id"], "job_id": job["id"]},
            ) from error
        return JobEnqueueResult(job, event, True)

    async def _resolve_idempotent_retry(self, job: Job, fingerprint: str) -> JobEnqueueResult:
        row = (
            await self._connection.execute(
                select(jobs).where(
                    jobs.c.task_id == job["task_id"],
                    jobs.c.idempotency_key == job["idempotency_key"],
                )
            )
        ).mappings().one()
        if row["request_fingerprint"] != fingerprint:
            raise IdempotencyConflict(
                "idempotency key was already used for a different job request",
                details={
                    "task_id": job["task_id"],
                    "idempotency_key": job["idempotency_key"],
                },
            )

        stored_job = _job_from_row(row)
        event_row = (
            await self._connection.execute(
                select(outbox_events).where(
                    outbox_events.c.aggregate_type == "job",
                    outbox_events.c.aggregate_id == stored_job["id"],
                    outbox_events.c.event_type == "job.requested",
                    outbox_events.c.sequence == stored_job["attempt"],
                )
            )
        ).mappings().one_or_none()
        if event_row is None:
            raise PersistenceInvariantError(
                "idempotent job exists without its outbox event",
                details={"job_id": stored_job["id"]},
            )
        return JobEnqueueResult(
            stored_job,
            cast(JobRequestedEvent, _event_from_row(event_row)),
            False,
        )

    async def get(self, job_id: str) -> Job:
        row = (
            await self._connection.execute(select(jobs).where(jobs.c.id == job_id))
        ).mappings().one_or_none()
        if row is None:
            raise EntityNotFound("job not found", details={"job_id": job_id})
        return _job_from_row(row)


class OutboxRepository:
    def __init__(self, connection: AsyncConnection) -> None:
        self._connection = connection

    async def pending(self, *, limit: int = 100) -> list[OutboxMessage]:
        return await self._load_pending(limit=limit, lock=False)

    async def claim_pending(self, *, limit: int = 100) -> list[OutboxMessage]:
        """Lock one dispatch batch, skipping rows held by another dispatcher."""

        return await self._load_pending(limit=limit, lock=True)

    async def _load_pending(
        self, *, limit: int, lock: bool
    ) -> list[OutboxMessage]:
        if limit < 1 or limit > 1000:
            raise ValueError("outbox batch limit must be between 1 and 1000")
        statement = (
            select(outbox_events)
            .where(
                outbox_events.c.published_at.is_(None),
                outbox_events.c.dead_lettered_at.is_(None),
                outbox_events.c.available_at <= func.now(),
            )
            .order_by(outbox_events.c.available_at, outbox_events.c.created_at)
            .limit(limit)
        )
        if lock:
            statement = statement.with_for_update(skip_locked=True)
        rows = (
            await self._connection.execute(statement)
        ).mappings().all()
        return [
            OutboxMessage(
                event=_event_from_row(row),
                publish_attempts=row["publish_attempts"],
                available_at=row["available_at"],
            )
            for row in rows
        ]

    async def mark_published(self, event_id: str, *, published_at: datetime) -> bool:
        result = await self._connection.execute(
            update(outbox_events)
            .where(
                outbox_events.c.id == event_id,
                outbox_events.c.published_at.is_(None),
                outbox_events.c.dead_lettered_at.is_(None),
            )
            .values(published_at=published_at)
        )
        return result.rowcount == 1

    async def mark_failed(
        self,
        event_id: str,
        *,
        error: dict[str, object],
        retry_after: timedelta,
        failed_at: datetime | None = None,
    ) -> bool:
        timestamp = failed_at or datetime.now(UTC)
        result = await self._connection.execute(
            update(outbox_events)
            .where(
                outbox_events.c.id == event_id,
                outbox_events.c.published_at.is_(None),
                outbox_events.c.dead_lettered_at.is_(None),
            )
            .values(
                publish_attempts=outbox_events.c.publish_attempts + 1,
                last_error=error,
                available_at=timestamp + retry_after,
            )
        )
        return result.rowcount == 1

    async def mark_dead_lettered(
        self,
        event_id: str,
        *,
        reason: dict[str, object],
        dead_lettered_at: datetime,
    ) -> bool:
        result = await self._connection.execute(
            update(outbox_events)
            .where(
                outbox_events.c.id == event_id,
                outbox_events.c.published_at.is_(None),
                outbox_events.c.dead_lettered_at.is_(None),
            )
            .values(
                dead_lettered_at=dead_lettered_at,
                dead_letter_reason=reason,
                last_error=reason,
            )
        )
        return result.rowcount == 1


class TaskEventRepository:
    def __init__(self, connection: AsyncConnection) -> None:
        self._connection = connection

    async def append(self, event: QueueEvent) -> None:
        validate_contract("QueueEvent", event)
        if event["event_type"] != "task.status_changed":
            raise ValueError("task event repository only accepts task.status_changed events")
        if event["payload"]["task_id"] != event["aggregate_id"]:
            raise PersistenceInvariantError(
                "task.status_changed event does not match its task",
                details={"mismatched_fields": ["payload.task_id"]},
            )
        try:
            await self._connection.execute(
                insert(task_events).values(
                    id=event["event_id"],
                    schema_version=event["schema_version"],
                    task_id=event["aggregate_id"],
                    event_type=event["event_type"],
                    sequence=event["sequence"],
                    occurred_at=_parse_datetime(event["occurred_at"]),
                    correlation_id=event["correlation_id"],
                    causation_id=event["causation_id"],
                    payload=event["payload"],
                )
            )
        except IntegrityError as error:
            raise EntityConflict(
                "task event sequence or identifier already exists",
                details={"event_id": event["event_id"]},
            ) from error


@dataclass(frozen=True, slots=True)
class Repositories:
    projects: ProjectRepository
    artifacts: ArtifactRepository
    tasks: TaskRepository
    jobs: JobRepository
    outbox: OutboxRepository
    task_events: TaskEventRepository

    def __init__(self, connection: AsyncConnection) -> None:
        object.__setattr__(self, "projects", ProjectRepository(connection))
        object.__setattr__(self, "artifacts", ArtifactRepository(connection))
        object.__setattr__(self, "tasks", TaskRepository(connection))
        object.__setattr__(self, "jobs", JobRepository(connection))
        object.__setattr__(self, "outbox", OutboxRepository(connection))
        object.__setattr__(self, "task_events", TaskEventRepository(connection))


def _project_values(project: Project) -> dict[str, object]:
    return {
        **project,
        "permission_mode": project["permission_mode"].value,
        "created_at": _parse_datetime(project["created_at"]),
    }


def _project_from_row(row: RowMapping) -> Project:
    return Project(
        schema_version=row["schema_version"],
        id=row["id"],
        name=row["name"],
        input_scope=row["input_scope"],
        permission_mode=PermissionMode(row["permission_mode"]),
        exploit_validation_enabled=row["exploit_validation_enabled"],
        resource_budget=row["resource_budget"],
        created_at=_format_datetime(row["created_at"]),
    )


def _artifact_values(artifact: Artifact) -> dict[str, object]:
    return {
        **artifact,
        "kind": artifact["kind"].value,
        "created_at": _parse_datetime(artifact["created_at"]),
    }


def _artifact_from_row(row: RowMapping) -> Artifact:
    return Artifact(
        schema_version=row["schema_version"],
        id=row["id"],
        project_id=row["project_id"],
        kind=ArtifactKind(row["kind"]),
        current_version_id=row["current_version_id"],
        created_at=_format_datetime(row["created_at"]),
    )


def _artifact_version_values(version: ArtifactVersion) -> dict[str, object]:
    return {
        **version,
        "created_at": _parse_datetime(version["created_at"]),
    }


def _artifact_version_from_row(row: RowMapping) -> ArtifactVersion:
    value = ArtifactVersion(
        schema_version=row["schema_version"],
        id=row["id"],
        artifact_id=row["artifact_id"],
        digest=row["digest"],
        object_ref=row["object_ref"],
        generation_config=row["generation_config"],
        created_at=_format_datetime(row["created_at"]),
    )
    if row["parent_version_id"] is not None:
        value["parent_version_id"] = row["parent_version_id"]
    if row["produced_by"] is not None:
        value["produced_by"] = row["produced_by"]
    return value


def _task_fingerprint(task: Task) -> str:
    return request_fingerprint(
        {
            "schema_version": task["schema_version"],
            "project_id": task["project_id"],
            "artifact_version_ids": task["artifact_version_ids"],
            "resource_budget": task["resource_budget"],
        }
    )


def _task_values(task: Task, fingerprint: str) -> dict[str, object]:
    return {
        **task,
        "status": task["status"].value,
        "result": task["result"].value if task["result"] is not None else None,
        "request_fingerprint": fingerprint,
        "created_at": _parse_datetime(task["created_at"]),
        "updated_at": _parse_datetime(task["updated_at"]),
    }


def _task_from_row(row: RowMapping) -> Task:
    return Task(
        schema_version=row["schema_version"],
        id=row["id"],
        project_id=row["project_id"],
        artifact_version_ids=row["artifact_version_ids"],
        status=TaskStatus(row["status"]),
        result=TaskResult(row["result"]) if row["result"] is not None else None,
        idempotency_key=row["idempotency_key"],
        resource_budget=row["resource_budget"],
        created_at=_format_datetime(row["created_at"]),
        updated_at=_format_datetime(row["updated_at"]),
    )


def _job_fingerprint(job: Job) -> str:
    return request_fingerprint(
        {
            "schema_version": job["schema_version"],
            "task_id": job["task_id"],
            "kind": job["kind"],
            "input_refs": job["input_refs"],
            "resource_budget": job["resource_budget"],
            "retry_policy": job["retry_policy"],
        }
    )


def _job_values(job: Job, fingerprint: str) -> dict[str, object]:
    return {
        **job,
        "kind": job["kind"].value,
        "status": job["status"].value,
        "request_fingerprint": fingerprint,
        "created_at": _parse_datetime(job["created_at"]),
        "updated_at": _parse_datetime(job["updated_at"]),
    }


def _job_from_row(row: RowMapping) -> Job:
    return Job(
        schema_version=row["schema_version"],
        id=row["id"],
        task_id=row["task_id"],
        kind=JobKind(row["kind"]),
        input_refs=row["input_refs"],
        status=JobStatus(row["status"]),
        idempotency_key=row["idempotency_key"],
        resource_budget=row["resource_budget"],
        retry_policy=row["retry_policy"],
        attempt=row["attempt"],
        lease=row["lease"],
        failure=row["failure"],
        created_at=_format_datetime(row["created_at"]),
        updated_at=_format_datetime(row["updated_at"]),
    )


def _ensure_event_matches_job(job: Job, event: JobRequestedEvent) -> None:
    payload = event["payload"]
    mismatches = {
        "aggregate_id": (event["aggregate_id"], job["id"]),
        "sequence": (event["sequence"], job["attempt"]),
        "payload.job_id": (payload["job_id"], job["id"]),
        "payload.task_id": (payload["task_id"], job["task_id"]),
        "payload.job_kind": (payload["job_kind"], job["kind"]),
        "payload.attempt": (payload["attempt"], job["attempt"]),
    }
    invalid = [name for name, (actual, expected) in mismatches.items() if actual != expected]
    if invalid:
        raise PersistenceInvariantError(
            "job.requested event does not match its job",
            details={"mismatched_fields": invalid},
        )


def _outbox_values(event: JobRequestedEvent) -> dict[str, object]:
    occurred_at = _parse_datetime(event["occurred_at"])
    return {
        "id": event["event_id"],
        "schema_version": event["schema_version"],
        "aggregate_type": "job",
        "aggregate_id": event["aggregate_id"],
        "event_type": event["event_type"],
        "sequence": event["sequence"],
        "occurred_at": occurred_at,
        "correlation_id": event["correlation_id"],
        "causation_id": event["causation_id"],
        "payload": event["payload"],
        "available_at": occurred_at,
    }


def _event_from_row(row: RowMapping) -> QueueEvent:
    return cast(
        QueueEvent,
        {
            "schema_version": row["schema_version"],
            "event_id": row["id"],
            "event_type": row["event_type"],
            "aggregate_id": row["aggregate_id"],
            "sequence": row["sequence"],
            "occurred_at": _format_datetime(row["occurred_at"]),
            "correlation_id": row["correlation_id"],
            "causation_id": row["causation_id"],
            "payload": row["payload"],
        },
    )


def _parse_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamps must include an explicit timezone")
    return parsed


def _format_datetime(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
