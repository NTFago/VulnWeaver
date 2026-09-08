"""Transaction-scoped repositories for control-plane facts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import cast
from uuid import uuid4

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
    Lease,
    PermissionMode,
    Project,
    QueueEvent,
    StructuredFailure,
    Task,
    TaskResult,
    TaskStatus,
    WorkerResult,
    validate_contract,
)

from vulnweaver_persistence.api_requests import ApiRequestRepository
from vulnweaver_persistence.errors import (
    EntityConflict,
    EntityNotFound,
    IdempotencyConflict,
    JobLeaseConflict,
    PersistenceInvariantError,
)
from vulnweaver_persistence.fingerprints import request_fingerprint
from vulnweaver_persistence.models import (
    artifact_versions,
    artifacts,
    job_attempt_failures,
    job_results,
    jobs,
    outbox_events,
    projects,
    task_events,
    tasks,
)
from vulnweaver_persistence.personal_auth import PersonalAuthRepository


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


class JobLeaseClaimOutcome(StrEnum):
    ACQUIRED = "acquired"
    ALREADY_OWNED = "already_owned"
    BUSY = "busy"
    COMPLETED = "completed"
    EXHAUSTED = "exhausted"
    BACKING_OFF = "backing_off"
    NOT_RUNNABLE = "not_runnable"


@dataclass(frozen=True, slots=True)
class JobLeaseClaim:
    job: Job
    outcome: JobLeaseClaimOutcome
    retry_after_seconds: float = 0.0


@dataclass(frozen=True, slots=True)
class JobCompletionResult:
    job: Job
    result: WorkerResult
    created: bool


@dataclass(frozen=True, slots=True)
class JobAttemptFailure:
    job_id: str
    attempt: int
    owner: str
    failure: StructuredFailure
    recorded_at: datetime


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
            (await self._connection.execute(select(projects).where(projects.c.id == project_id)))
            .mappings()
            .one_or_none()
        )
        if row is None:
            raise EntityNotFound("project not found", details={"project_id": project_id})
        return _project_from_row(row)

    async def list(self) -> list[Project]:
        rows = (
            await self._connection.execute(select(projects).order_by(projects.c.created_at.desc()))
        ).mappings()
        return [_project_from_row(row) for row in rows]


class ArtifactRepository:
    def __init__(self, connection: AsyncConnection) -> None:
        self._connection = connection

    async def add(self, artifact: Artifact) -> Artifact:
        validate_contract("Artifact", artifact)
        values = _artifact_values(artifact)
        # Break the cyclic FK only inside this transaction; add_version installs
        # the contract's non-null current version before any other transaction can read it.
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
            (await self._connection.execute(select(artifacts).where(artifacts.c.id == artifact_id)))
            .mappings()
            .one_or_none()
        )
        if row is None:
            raise EntityNotFound("artifact not found", details={"artifact_id": artifact_id})
        return _artifact_from_row(row)

    async def get_version(self, version_id: str) -> ArtifactVersion:
        row = (
            (
                await self._connection.execute(
                    select(artifact_versions).where(artifact_versions.c.id == version_id)
                )
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            raise EntityNotFound(
                "artifact version not found",
                details={"artifact_version_id": version_id},
            )
        return _artifact_version_from_row(row)

    async def list_for_project(self, project_id: str) -> list[Artifact]:
        rows = (
            await self._connection.execute(
                select(artifacts)
                .where(artifacts.c.project_id == project_id)
                .order_by(artifacts.c.created_at.desc())
            )
        ).mappings()
        return [_artifact_from_row(row) for row in rows]

    async def list_versions(self, artifact_id: str) -> list[ArtifactVersion]:
        rows = (
            await self._connection.execute(
                select(artifact_versions)
                .where(artifact_versions.c.artifact_id == artifact_id)
                .order_by(artifact_versions.c.created_at.desc())
            )
        ).mappings()
        return [_artifact_version_from_row(row) for row in rows]

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
                (
                    await self._connection.execute(
                        select(artifact_versions).where(
                            artifact_versions.c.artifact_id == version["artifact_id"],
                            artifact_versions.c.digest == version["digest"],
                        )
                    )
                )
                .mappings()
                .one()
            )
            stored = _artifact_version_from_row(row)
            created = False
        else:
            stored = version
            created = True

        if created:
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
            (
                await self._connection.execute(
                    select(tasks).where(
                        tasks.c.project_id == task["project_id"],
                        tasks.c.idempotency_key == task["idempotency_key"],
                    )
                )
            )
            .mappings()
            .one()
        )
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
            (await self._connection.execute(select(tasks).where(tasks.c.id == task_id)))
            .mappings()
            .one_or_none()
        )
        if row is None:
            raise EntityNotFound("task not found", details={"task_id": task_id})
        return _task_from_row(row)

    async def list(self) -> list[Task]:
        rows = (
            await self._connection.execute(select(tasks).order_by(tasks.c.created_at.desc()))
        ).mappings()
        return [_task_from_row(row) for row in rows]

    async def list_for_project(self, project_id: str) -> list[Task]:
        rows = (
            await self._connection.execute(
                select(tasks)
                .where(tasks.c.project_id == project_id)
                .order_by(tasks.c.created_at.desc())
            )
        ).mappings()
        return [_task_from_row(row) for row in rows]

    async def cancel(self, task_id: str) -> Task:
        row = (
            (
                await self._connection.execute(
                    update(tasks)
                    .where(
                        tasks.c.id == task_id,
                        tasks.c.status.not_in(("completed", "failed", "cancelled")),
                    )
                    .values(
                        status="cancelled",
                        result=None,
                        updated_at=func.now(),
                        state_version=tasks.c.state_version + 1,
                    )
                    .returning(*tasks.c)
                )
            )
            .mappings()
            .one_or_none()
        )
        if row is not None:
            return _task_from_row(row)
        return await self.get(task_id)


class JobRepository:
    def __init__(self, connection: AsyncConnection) -> None:
        self._connection = connection

    async def enqueue_with_outbox(self, job: Job, event: JobRequestedEvent) -> JobEnqueueResult:
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
            (
                await self._connection.execute(
                    select(jobs).where(
                        jobs.c.task_id == job["task_id"],
                        jobs.c.idempotency_key == job["idempotency_key"],
                    )
                )
            )
            .mappings()
            .one()
        )
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
            (
                await self._connection.execute(
                    select(outbox_events).where(
                        outbox_events.c.aggregate_type == "job",
                        outbox_events.c.aggregate_id == stored_job["id"],
                        outbox_events.c.event_type == "job.requested",
                        outbox_events.c.sequence == stored_job["attempt"],
                    )
                )
            )
            .mappings()
            .one_or_none()
        )
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
            (await self._connection.execute(select(jobs).where(jobs.c.id == job_id)))
            .mappings()
            .one_or_none()
        )
        if row is None:
            raise EntityNotFound("job not found", details={"job_id": job_id})
        return _job_from_row(row)

    async def list_for_task(self, task_id: str) -> list[Job]:
        rows = (
            await self._connection.execute(
                select(jobs).where(jobs.c.task_id == task_id).order_by(jobs.c.created_at)
            )
        ).mappings()
        return [_job_from_row(row) for row in rows]

    async def cancel_for_task(self, task_id: str) -> int:
        result = await self._connection.execute(
            update(jobs)
            .where(
                jobs.c.task_id == task_id,
                jobs.c.status.not_in(("succeeded", "failed", "cancelled")),
            )
            .values(
                status="cancelled",
                lease=None,
                failure=None,
                updated_at=func.now(),
                state_version=jobs.c.state_version + 1,
            )
        )
        return result.rowcount

    async def claim_lease(
        self,
        job_id: str,
        *,
        owner: str,
        lease_seconds: int,
        heartbeat_interval_seconds: int,
    ) -> JobLeaseClaim:
        """Atomically claim queued work or take over an expired running Job."""

        if heartbeat_interval_seconds < 1:
            raise ValueError("heartbeat interval must be positive")
        if lease_seconds <= heartbeat_interval_seconds:
            raise ValueError("lease duration must exceed its heartbeat interval")

        row, now = await self._job_with_database_time(job_id, lock=False)
        current = _job_from_row(row)
        read_only = _read_only_claim_outcome(row, current, now, owner)
        if read_only is not None:
            return read_only

        # Only mutation candidates take a row lock. Re-check after locking because
        # another claimant may have changed the Job between the two reads.
        row, now = await self._job_with_database_time(job_id, lock=True)
        current = _job_from_row(row)
        read_only = _read_only_claim_outcome(row, current, now, owner)
        if read_only is not None:
            return read_only

        exhausted = current["attempt"] >= current["retry_policy"]["max_attempts"]
        fencing_token = uuid4().hex

        lease = Lease(
            owner=owner,
            fencing_token=fencing_token,
            expires_at=_format_datetime(now + timedelta(seconds=lease_seconds)),
            heartbeat_interval_seconds=heartbeat_interval_seconds,
        )
        validate_contract("Lease", lease)
        await self._connection.execute(
            update(jobs)
            .where(jobs.c.id == job_id, jobs.c.state_version == row["state_version"])
            .values(
                status=JobStatus.RUNNING.value,
                attempt=jobs.c.attempt if exhausted else jobs.c.attempt + 1,
                retry_not_before=None,
                lease=lease,
                failure=None,
                updated_at=now,
                state_version=jobs.c.state_version + 1,
            )
        )
        outcome = JobLeaseClaimOutcome.EXHAUSTED if exhausted else JobLeaseClaimOutcome.ACQUIRED
        return JobLeaseClaim(await self.get(job_id), outcome)

    async def renew_lease(
        self, job_id: str, *, owner: str, fencing_token: str, lease_seconds: int
    ) -> Job:
        """Extend an active lease only while its owner still holds it."""

        row, now = await self._job_with_database_time(job_id, lock=True)
        current = _job_from_row(row)
        lease = current["lease"]
        if current["status"] is not JobStatus.RUNNING or lease is None:
            raise JobLeaseConflict("job has no active lease", details={"job_id": job_id})
        if (
            lease["owner"] != owner
            or lease.get("fencing_token") != fencing_token
            or _parse_datetime(lease["expires_at"]) <= now
        ):
            raise JobLeaseConflict(
                "job lease is no longer owned by this worker",
                details={"job_id": job_id, "owner": owner},
            )
        if lease_seconds <= lease["heartbeat_interval_seconds"]:
            raise ValueError("lease duration must exceed its heartbeat interval")

        renewed = Lease(
            owner=owner,
            fencing_token=fencing_token,
            expires_at=_format_datetime(now + timedelta(seconds=lease_seconds)),
            heartbeat_interval_seconds=lease["heartbeat_interval_seconds"],
        )
        await self._connection.execute(
            update(jobs)
            .where(jobs.c.id == job_id, jobs.c.state_version == row["state_version"])
            .values(
                lease=renewed,
                updated_at=now,
                state_version=jobs.c.state_version + 1,
            )
        )
        return await self.get(job_id)

    async def release_lease(
        self,
        job_id: str,
        *,
        owner: str,
        fencing_token: str,
        refund_attempt: bool = True,
    ) -> Job:
        """Return unfinished work to the queued state during retry or graceful stop."""

        row, now = await self._job_with_database_time(job_id, lock=True)
        current = _job_from_row(row)
        lease = current["lease"]
        if (
            current["status"] is not JobStatus.RUNNING
            or lease is None
            or lease["owner"] != owner
            or lease.get("fencing_token") != fencing_token
        ):
            raise JobLeaseConflict(
                "job lease is no longer owned by this worker",
                details={"job_id": job_id, "owner": owner},
            )
        await self._connection.execute(
            update(jobs)
            .where(jobs.c.id == job_id, jobs.c.state_version == row["state_version"])
            .values(
                status=JobStatus.QUEUED.value,
                attempt=jobs.c.attempt - 1 if refund_attempt else jobs.c.attempt,
                retry_not_before=None,
                lease=None,
                updated_at=now,
                state_version=jobs.c.state_version + 1,
            )
        )
        return await self.get(job_id)

    async def complete(
        self, result: WorkerResult, *, owner: str, fencing_token: str
    ) -> JobCompletionResult:
        """Persist one immutable terminal result and update its Job atomically."""

        validate_contract("WorkerResult", result)
        _ensure_terminal_worker_result(result)
        fingerprint = _worker_result_fingerprint(result)
        row, now = await self._job_with_database_time(result["job_id"], lock=True)
        repeated = await self._existing_completion(row, result, fingerprint)
        if repeated is not None:
            return repeated

        current = _job_from_row(row)
        lease = current["lease"]
        if (
            current["status"] is not JobStatus.RUNNING
            or lease is None
            or lease["owner"] != owner
            or lease.get("fencing_token") != fencing_token
            or _parse_datetime(lease["expires_at"]) <= now
        ):
            raise JobLeaseConflict(
                "job lease is no longer owned by this worker",
                details={"job_id": result["job_id"], "owner": owner},
            )

        return await self._persist_completion(row, now, result, fingerprint)

    async def record_attempt_failure(
        self,
        job_id: str,
        *,
        attempt: int,
        owner: str,
        fencing_token: str,
        failure: StructuredFailure,
    ) -> Job:
        """Append one retryable failure and release that exact execution attempt."""

        validate_contract("StructuredFailure", failure)
        fingerprint = _structured_failure_fingerprint(failure)
        row, now = await self._job_with_database_time(job_id, lock=True)
        current = _job_from_row(row)
        existing_row = (
            (
                await self._connection.execute(
                    select(job_attempt_failures).where(
                        job_attempt_failures.c.job_id == job_id,
                        job_attempt_failures.c.attempt == attempt,
                    )
                )
            )
            .mappings()
            .one_or_none()
        )
        if existing_row is not None:
            if existing_row["failure_fingerprint"] != fingerprint:
                raise IdempotencyConflict(
                    "job attempt already has a different failure",
                    details={"job_id": job_id, "attempt": attempt},
                )
            return current

        lease = current["lease"]
        retry_policy = current["retry_policy"]
        if (
            not failure["retryable"]
            or failure["kind"] not in retry_policy["retryable_failure_kinds"]
            or attempt >= retry_policy["max_attempts"]
        ):
            raise PersistenceInvariantError(
                "job failure is not eligible for another attempt",
                details={"job_id": job_id, "attempt": attempt},
            )
        if (
            current["status"] is not JobStatus.RUNNING
            or current["attempt"] != attempt
            or lease is None
            or lease["owner"] != owner
            or lease.get("fencing_token") != fencing_token
            or _parse_datetime(lease["expires_at"]) <= now
        ):
            raise JobLeaseConflict(
                "job attempt is no longer owned by this worker",
                details={"job_id": job_id, "attempt": attempt, "owner": owner},
            )
        await self._connection.execute(
            insert(job_attempt_failures).values(
                job_id=job_id,
                attempt=attempt,
                schema_version="1.0.0",
                owner=owner,
                failure=failure,
                failure_fingerprint=fingerprint,
                recorded_at=now,
            )
        )
        await self._connection.execute(
            update(jobs)
            .where(jobs.c.id == job_id, jobs.c.state_version == row["state_version"])
            .values(
                status=JobStatus.QUEUED.value,
                retry_not_before=(now + timedelta(seconds=retry_policy["backoff_seconds"])),
                lease=None,
                updated_at=now,
                state_version=jobs.c.state_version + 1,
            )
        )
        return await self.get(job_id)

    async def attempt_failures(self, job_id: str) -> list[JobAttemptFailure]:
        rows = (
            (
                await self._connection.execute(
                    select(job_attempt_failures)
                    .where(job_attempt_failures.c.job_id == job_id)
                    .order_by(job_attempt_failures.c.attempt)
                )
            )
            .mappings()
            .all()
        )
        return [_job_attempt_failure_from_row(row) for row in rows]

    async def fail_exhausted(
        self, result: WorkerResult, *, owner: str, fencing_token: str
    ) -> JobCompletionResult:
        """Persist an exhausted Job failure without granting another execution lease."""

        validate_contract("WorkerResult", result)
        _ensure_terminal_worker_result(result)
        if result["status"] is not JobStatus.FAILED or result["failure"] is None:
            raise PersistenceInvariantError(
                "exhausted job result must be a structured failure",
                details={"job_id": result["job_id"]},
            )
        fingerprint = _worker_result_fingerprint(result)
        row, now = await self._job_with_database_time(result["job_id"], lock=True)
        repeated = await self._existing_completion(row, result, fingerprint)
        if repeated is not None:
            return repeated

        current = _job_from_row(row)
        lease = current["lease"]
        if current["attempt"] < current["retry_policy"]["max_attempts"]:
            raise PersistenceInvariantError(
                "job has not exhausted its permitted execution attempts",
                details={"job_id": result["job_id"]},
            )
        if (
            current["status"] is not JobStatus.RUNNING
            or lease is None
            or lease["owner"] != owner
            or lease.get("fencing_token") != fencing_token
            or _parse_datetime(lease["expires_at"]) <= now
        ):
            raise JobLeaseConflict(
                "job exhaustion settlement lease is no longer owned by this worker",
                details={"job_id": result["job_id"], "owner": owner},
            )
        return await self._persist_completion(row, now, result, fingerprint)

    async def _existing_completion(
        self, row: RowMapping, result: WorkerResult, fingerprint: str
    ) -> JobCompletionResult | None:
        existing_row = (
            (
                await self._connection.execute(
                    select(job_results).where(job_results.c.job_id == result["job_id"])
                )
            )
            .mappings()
            .one_or_none()
        )
        if existing_row is None:
            return None
        if existing_row["result_fingerprint"] != fingerprint:
            raise IdempotencyConflict(
                "job already has a different terminal result",
                details={"job_id": result["job_id"]},
            )
        return JobCompletionResult(
            _job_from_row(row),
            _worker_result_from_row(existing_row),
            False,
        )

    async def _persist_completion(
        self,
        row: RowMapping,
        now: datetime,
        result: WorkerResult,
        fingerprint: str,
    ) -> JobCompletionResult:
        await self._connection.execute(
            insert(job_results).values(
                job_id=result["job_id"],
                schema_version=result["schema_version"],
                status=str(result["status"]),
                produced_artifact_version_ids=result["produced_artifact_version_ids"],
                evidence_ids=result["evidence_ids"],
                failure=result["failure"],
                result_fingerprint=fingerprint,
                completed_at=now,
            )
        )
        await self._connection.execute(
            update(jobs)
            .where(
                jobs.c.id == result["job_id"],
                jobs.c.state_version == row["state_version"],
            )
            .values(
                status=str(result["status"]),
                failure=result["failure"],
                retry_not_before=None,
                lease=None,
                updated_at=now,
                state_version=jobs.c.state_version + 1,
            )
        )
        return JobCompletionResult(await self.get(result["job_id"]), result, True)

    async def _job_with_database_time(
        self, job_id: str, *, lock: bool
    ) -> tuple[RowMapping, datetime]:
        statement = select(*jobs.c, func.now().label("_database_now")).where(jobs.c.id == job_id)
        if lock:
            statement = statement.with_for_update()
        row = (await self._connection.execute(statement)).mappings().one_or_none()
        if row is None:
            raise EntityNotFound("job not found", details={"job_id": job_id})
        return row, row["_database_now"]


class OutboxRepository:
    def __init__(self, connection: AsyncConnection) -> None:
        self._connection = connection

    async def pending(self, *, limit: int = 100) -> list[OutboxMessage]:
        return await self._load_pending(limit=limit, lock=False)

    async def claim_pending(self, *, limit: int = 100) -> list[OutboxMessage]:
        """Lock one dispatch batch, skipping rows held by another dispatcher."""

        return await self._load_pending(limit=limit, lock=True)

    async def add(self, event: QueueEvent) -> None:
        validate_contract("QueueEvent", event)
        await self._connection.execute(insert(outbox_events).values(_outbox_values(event)))

    async def _load_pending(self, *, limit: int, lock: bool) -> list[OutboxMessage]:
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
        rows = (await self._connection.execute(statement)).mappings().all()
        return [
            OutboxMessage(
                event=_event_from_row(row),
                publish_attempts=row["publish_attempts"],
                available_at=row["available_at"],
            )
            for row in rows
        ]

    async def mark_published(self, event_id: str) -> bool:
        result = await self._connection.execute(
            update(outbox_events)
            .where(
                outbox_events.c.id == event_id,
                outbox_events.c.published_at.is_(None),
                outbox_events.c.dead_lettered_at.is_(None),
            )
            .values(published_at=func.now())
        )
        return result.rowcount == 1

    async def mark_failed(
        self,
        event_id: str,
        *,
        error: dict[str, object],
        retry_after: timedelta,
    ) -> bool:
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
                available_at=func.now() + retry_after,
            )
        )
        return result.rowcount == 1

    async def mark_dead_lettered(
        self,
        event_id: str,
        *,
        reason: dict[str, object],
    ) -> bool:
        result = await self._connection.execute(
            update(outbox_events)
            .where(
                outbox_events.c.id == event_id,
                outbox_events.c.published_at.is_(None),
                outbox_events.c.dead_lettered_at.is_(None),
            )
            .values(
                dead_lettered_at=func.now(),
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

    async def list_after(
        self, task_id: str, *, after_sequence: int = -1, limit: int = 100
    ) -> list[QueueEvent]:
        rows = (
            await self._connection.execute(
                select(task_events)
                .where(task_events.c.task_id == task_id, task_events.c.sequence > after_sequence)
                .order_by(task_events.c.sequence)
                .limit(limit)
            )
        ).mappings()
        return [_task_event_from_row(row) for row in rows]

    async def next_sequence(self, task_id: str) -> int:
        value = await self._connection.scalar(
            select(func.coalesce(func.max(task_events.c.sequence), -1) + 1).where(
                task_events.c.task_id == task_id
            )
        )
        assert value is not None
        return int(value)


@dataclass(frozen=True, slots=True)
class Repositories:
    projects: ProjectRepository
    artifacts: ArtifactRepository
    tasks: TaskRepository
    jobs: JobRepository
    outbox: OutboxRepository
    task_events: TaskEventRepository
    api_requests: ApiRequestRepository
    personal_auth: PersonalAuthRepository

    def __init__(self, connection: AsyncConnection) -> None:
        object.__setattr__(self, "projects", ProjectRepository(connection))
        object.__setattr__(self, "artifacts", ArtifactRepository(connection))
        object.__setattr__(self, "tasks", TaskRepository(connection))
        object.__setattr__(self, "jobs", JobRepository(connection))
        object.__setattr__(self, "outbox", OutboxRepository(connection))
        object.__setattr__(self, "task_events", TaskEventRepository(connection))
        object.__setattr__(self, "api_requests", ApiRequestRepository(connection))
        object.__setattr__(self, "personal_auth", PersonalAuthRepository(connection))


def _project_values(project: Project) -> dict[str, object]:
    return {
        **project,
        "permission_mode": str(project["permission_mode"]),
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
        "kind": str(artifact["kind"]),
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
        "status": str(task["status"]),
        "result": str(task["result"]) if task["result"] is not None else None,
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
        "kind": str(job["kind"]),
        "status": str(job["status"]),
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


def _worker_result_fingerprint(result: WorkerResult) -> str:
    return request_fingerprint(
        {
            "schema_version": result["schema_version"],
            "job_id": result["job_id"],
            "status": result["status"],
            "produced_artifact_version_ids": sorted(result["produced_artifact_version_ids"]),
            "evidence_ids": sorted(result["evidence_ids"]),
            "failure": result["failure"],
        }
    )


def _read_only_claim_outcome(
    row: RowMapping,
    current: Job,
    now: datetime,
    owner: str,
) -> JobLeaseClaim | None:
    status = current["status"]
    if status is JobStatus.SUCCEEDED:
        return JobLeaseClaim(current, JobLeaseClaimOutcome.COMPLETED)
    if status not in {JobStatus.PENDING, JobStatus.QUEUED, JobStatus.RUNNING}:
        return JobLeaseClaim(current, JobLeaseClaimOutcome.NOT_RUNNABLE)

    lease = current["lease"]
    if (
        status is JobStatus.RUNNING
        and lease is not None
        and _parse_datetime(lease["expires_at"]) > now
    ):
        outcome = (
            JobLeaseClaimOutcome.ALREADY_OWNED
            if lease["owner"] == owner
            else JobLeaseClaimOutcome.BUSY
        )
        return JobLeaseClaim(current, outcome)

    retry_not_before = row["retry_not_before"]
    if status is JobStatus.QUEUED and retry_not_before is not None and retry_not_before > now:
        return JobLeaseClaim(
            current,
            JobLeaseClaimOutcome.BACKING_OFF,
            retry_after_seconds=(retry_not_before - now).total_seconds(),
        )
    return None


def _structured_failure_fingerprint(failure: StructuredFailure) -> str:
    return request_fingerprint(
        {
            "code": failure["code"],
            "kind": failure["kind"],
            "message": failure["message"],
            "retryable": failure["retryable"],
            "details": failure["details"],
        }
    )


def _job_attempt_failure_from_row(row: RowMapping) -> JobAttemptFailure:
    return JobAttemptFailure(
        job_id=row["job_id"],
        attempt=row["attempt"],
        owner=row["owner"],
        failure=row["failure"],
        recorded_at=row["recorded_at"],
    )


def _worker_result_from_row(row: RowMapping) -> WorkerResult:
    return WorkerResult(
        schema_version=row["schema_version"],
        job_id=row["job_id"],
        status=JobStatus(row["status"]),
        produced_artifact_version_ids=row["produced_artifact_version_ids"],
        evidence_ids=row["evidence_ids"],
        failure=row["failure"],
    )


def _ensure_terminal_worker_result(result: WorkerResult) -> None:
    if result["status"] not in {
        JobStatus.SUCCEEDED,
        JobStatus.FAILED,
        JobStatus.CANCELLED,
    }:
        raise PersistenceInvariantError(
            "worker result must have a terminal status",
            details={"job_id": result["job_id"], "status": result["status"]},
        )
    if (result["status"] is JobStatus.FAILED) != (result["failure"] is not None):
        raise PersistenceInvariantError(
            "worker result failure must match its terminal status",
            details={"job_id": result["job_id"], "status": result["status"]},
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


def _outbox_values(event: QueueEvent) -> dict[str, object]:
    occurred_at = _parse_datetime(event["occurred_at"])
    return {
        "id": event["event_id"],
        "schema_version": event["schema_version"],
        "aggregate_type": "job" if event["event_type"].startswith("job.") else "task",
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


def _task_event_from_row(row: RowMapping) -> QueueEvent:
    return cast(
        QueueEvent,
        {
            "schema_version": row["schema_version"],
            "event_id": row["id"],
            "event_type": row["event_type"],
            "aggregate_id": row["task_id"],
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
