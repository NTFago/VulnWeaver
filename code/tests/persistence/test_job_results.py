from __future__ import annotations

import asyncio
import copy
import sys

import pytest
from sqlalchemy import func, select
from vulnweaver_contracts import (
    FailureKind,
    JobStatus,
    SchemaVersion,
    StructuredFailure,
    WorkerResult,
)
from vulnweaver_persistence import (
    Database,
    DatabaseSettings,
    IdempotencyConflict,
    JobLeaseConflict,
    PersistenceInvariantError,
)
from vulnweaver_persistence.models import job_results

from tests.persistence.factories import (
    artifact,
    artifact_version,
    job,
    job_event,
    project,
    task,
)

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


@pytest.fixture(scope="module")
def result_database_url(persistence_database_url: str) -> str:
    async def seed() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        try:
            async with database.transaction() as repositories:
                await repositories.projects.add(project("project:t06-results"))
                await repositories.artifacts.add(
                    artifact(
                        "artifact:t06-results",
                        project_id="project:t06-results",
                        current_version_id="artifact-version:t06-results",
                    )
                )
                await repositories.artifacts.add_version(
                    artifact_version(
                        "artifact-version:t06-results",
                        artifact_id="artifact:t06-results",
                    )
                )
                await repositories.tasks.create(
                    task(
                        "task:t06-results",
                        project_id="project:t06-results",
                        artifact_version_ids=["artifact-version:t06-results"],
                        idempotency_key="task:t06-results-key",
                    )
                )
        finally:
            await database.dispose()

    asyncio.run(seed())
    return persistence_database_url


def _worker_result(job_id: str, *, status: JobStatus = JobStatus.SUCCEEDED) -> WorkerResult:
    return WorkerResult(
        schema_version=SchemaVersion.VALUE_1_0_0,
        job_id=job_id,
        status=status,
        produced_artifact_version_ids=["artifact-version:t06-output"],
        evidence_ids=["evidence:t06"],
        failure=None,
    )


async def _enqueue_and_claim(
    database: Database,
    job_id: str,
    owner: str,
    *,
    retryable_failure_kinds: list[FailureKind] | None = None,
) -> None:
    value = job(
        job_id,
        task_id="task:t06-results",
        idempotency_key=f"{job_id}-key",
    )
    value["retry_policy"]["retryable_failure_kinds"] = (
        [FailureKind.TOOL] if retryable_failure_kinds is None else retryable_failure_kinds
    )
    async with database.transaction() as repositories:
        await repositories.jobs.enqueue_with_outbox(
            value,
            job_event(value, f"event:{job_id}"),
        )
        await repositories.jobs.claim_lease(
            job_id,
            owner=owner,
            lease_seconds=60,
            heartbeat_interval_seconds=10,
        )


def test_terminal_result_and_job_state_are_committed_once(
    result_database_url: str,
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(result_database_url))
        result = _worker_result("job:t06-result-once")
        try:
            await _enqueue_and_claim(database, result["job_id"], "worker:t06-a")
            async with database.transaction() as repositories:
                first = await repositories.jobs.complete(result, owner="worker:t06-a")
            assert first.created
            assert first.job["status"] is JobStatus.SUCCEEDED
            assert first.job["lease"] is None

            # A retry after an ACK/network loss does not require the already-released lease.
            async with database.transaction() as repositories:
                repeated = await repositories.jobs.complete(result, owner="worker:t06-retry")
            assert not repeated.created
            assert repeated.result == result

            async with database.engine.connect() as connection:
                count = (
                    await connection.execute(
                        select(func.count())
                        .select_from(job_results)
                        .where(job_results.c.job_id == result["job_id"])
                    )
                ).scalar_one()
            assert count == 1
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_conflicting_terminal_result_is_rejected(result_database_url: str) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(result_database_url))
        result = _worker_result("job:t06-result-conflict")
        try:
            await _enqueue_and_claim(database, result["job_id"], "worker:t06-a")
            async with database.transaction() as repositories:
                await repositories.jobs.complete(result, owner="worker:t06-a")

            conflicting = copy.deepcopy(result)
            conflicting["evidence_ids"] = ["evidence:different"]
            with pytest.raises(IdempotencyConflict):
                async with database.transaction() as repositories:
                    await repositories.jobs.complete(conflicting, owner="worker:t06-a")
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_only_active_lease_owner_can_create_result(result_database_url: str) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(result_database_url))
        result = _worker_result("job:t06-result-owner")
        try:
            await _enqueue_and_claim(database, result["job_id"], "worker:t06-a")
            with pytest.raises(JobLeaseConflict):
                async with database.transaction() as repositories:
                    await repositories.jobs.complete(result, owner="worker:t06-other")

            async with database.transaction() as repositories:
                stored = await repositories.jobs.get(result["job_id"])
            assert stored["status"] is JobStatus.RUNNING
            async with database.engine.connect() as connection:
                count = (
                    await connection.execute(
                        select(func.count())
                        .select_from(job_results)
                        .where(job_results.c.job_id == result["job_id"])
                    )
                ).scalar_one()
            assert count == 0
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_worker_result_requires_terminal_status(result_database_url: str) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(result_database_url))
        try:
            with pytest.raises(PersistenceInvariantError):
                async with database.transaction() as repositories:
                    await repositories.jobs.complete(
                        _worker_result("job:missing", status=JobStatus.RUNNING),
                        owner="worker:t06-a",
                    )
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_retryable_attempt_failure_is_append_only_and_idempotent(
    result_database_url: str,
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(result_database_url))
        job_id = "job:t06-attempt-failure"
        failure = StructuredFailure(
            code="test.retryable",
            kind=FailureKind.TOOL,
            message="safe retryable failure",
            retryable=True,
            details={"tool": "test-double"},
        )
        try:
            await _enqueue_and_claim(database, job_id, "worker:t06-a")
            async with database.transaction() as repositories:
                released = await repositories.jobs.record_attempt_failure(
                    job_id,
                    attempt=1,
                    owner="worker:t06-a",
                    failure=failure,
                )
            assert released["status"] is JobStatus.QUEUED
            assert released["lease"] is None

            async with database.transaction() as repositories:
                repeated = await repositories.jobs.record_attempt_failure(
                    job_id,
                    attempt=1,
                    owner="worker:t06-a",
                    failure=failure,
                )
                history = await repositories.jobs.attempt_failures(job_id)
            assert repeated["status"] is JobStatus.QUEUED
            assert len(history) == 1
            assert history[0].attempt == 1
            assert history[0].owner == "worker:t06-a"
            assert history[0].failure == failure

            conflicting = copy.deepcopy(failure)
            conflicting["message"] = "different failure"
            with pytest.raises(IdempotencyConflict):
                async with database.transaction() as repositories:
                    await repositories.jobs.record_attempt_failure(
                        job_id,
                        attempt=1,
                        owner="worker:t06-a",
                        failure=conflicting,
                    )
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_attempt_failure_cannot_bypass_retry_kind_policy(
    result_database_url: str,
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(result_database_url))
        job_id = "job:t06-attempt-policy"
        failure = StructuredFailure(
            code="test.retryable",
            kind=FailureKind.TOOL,
            message="safe retryable failure",
            retryable=True,
            details={},
        )
        try:
            await _enqueue_and_claim(
                database,
                job_id,
                "worker:t06-a",
                retryable_failure_kinds=[],
            )
            with pytest.raises(PersistenceInvariantError):
                async with database.transaction() as repositories:
                    await repositories.jobs.record_attempt_failure(
                        job_id,
                        attempt=1,
                        owner="worker:t06-a",
                        failure=failure,
                    )
            async with database.transaction() as repositories:
                stored = await repositories.jobs.get(job_id)
                history = await repositories.jobs.attempt_failures(job_id)
            assert stored["status"] is JobStatus.RUNNING
            assert history == []
        finally:
            await database.dispose()

    asyncio.run(scenario())
