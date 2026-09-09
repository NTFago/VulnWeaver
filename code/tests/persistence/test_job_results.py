from __future__ import annotations

import asyncio
import copy
from datetime import UTC, datetime

import pytest
from sqlalchemy import func, select, update
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
    JobLeaseClaimOutcome,
    JobLeaseConflict,
    PersistenceInvariantError,
)
from vulnweaver_persistence.models import job_results, jobs

from tests.persistence.factories import (
    artifact,
    artifact_version,
    job,
    job_event,
    project,
    task,
)


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
    max_attempts: int = 2,
    backoff_seconds: float = 1,
) -> str:
    value = job(
        job_id,
        task_id="task:t06-results",
        idempotency_key=f"{job_id}-key",
    )
    value["retry_policy"]["retryable_failure_kinds"] = (
        [FailureKind.TOOL] if retryable_failure_kinds is None else retryable_failure_kinds
    )
    value["retry_policy"]["max_attempts"] = max_attempts
    value["retry_policy"]["backoff_seconds"] = backoff_seconds
    async with database.transaction() as repositories:
        await repositories.jobs.enqueue_with_outbox(
            value,
            job_event(value, f"event:{job_id}"),
        )
        claim = await repositories.jobs.claim_lease(
            job_id,
            owner=owner,
            lease_seconds=60,
            heartbeat_interval_seconds=10,
        )
    assert claim.job["lease"] is not None
    return claim.job["lease"]["fencing_token"]


def test_terminal_result_and_job_state_are_committed_once(
    result_database_url: str,
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(result_database_url))
        result = _worker_result("job:t06-result-once")
        try:
            token = await _enqueue_and_claim(database, result["job_id"], "worker:t06-a")
            async with database.transaction() as repositories:
                first = await repositories.jobs.complete(
                    result, owner="worker:t06-a", fencing_token=token
                )
            assert first.created
            assert first.job["status"] is JobStatus.SUCCEEDED
            assert first.job["lease"] is None

            # A retry after an ACK/network loss does not require the already-released lease.
            async with database.transaction() as repositories:
                repeated = await repositories.jobs.complete(
                    result, owner="worker:t06-retry", fencing_token="replay"
                )
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
            token = await _enqueue_and_claim(database, result["job_id"], "worker:t06-a")
            async with database.transaction() as repositories:
                await repositories.jobs.complete(result, owner="worker:t06-a", fencing_token=token)

            conflicting = copy.deepcopy(result)
            conflicting["evidence_ids"] = ["evidence:different"]
            with pytest.raises(IdempotencyConflict):
                async with database.transaction() as repositories:
                    await repositories.jobs.complete(
                        conflicting, owner="worker:t06-a", fencing_token=token
                    )
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_terminal_result_replay_ignores_set_order(result_database_url: str) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(result_database_url))
        result = _worker_result("job:t06-result-order")
        result["produced_artifact_version_ids"] = ["artifact-version:b", "artifact-version:a"]
        result["evidence_ids"] = ["evidence:b", "evidence:a"]
        try:
            token = await _enqueue_and_claim(database, result["job_id"], "worker:t06-a")
            async with database.transaction() as repositories:
                first = await repositories.jobs.complete(
                    result, owner="worker:t06-a", fencing_token=token
                )
            replay = copy.deepcopy(result)
            replay["produced_artifact_version_ids"].reverse()
            replay["evidence_ids"].reverse()
            async with database.transaction() as repositories:
                repeated = await repositories.jobs.complete(
                    replay, owner="worker:t06-replay", fencing_token="replay"
                )
            assert first.created
            assert not repeated.created
            assert repeated.result == result
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_only_active_lease_owner_can_create_result(result_database_url: str) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(result_database_url))
        result = _worker_result("job:t06-result-owner")
        try:
            token = await _enqueue_and_claim(database, result["job_id"], "worker:t06-a")
            with pytest.raises(JobLeaseConflict):
                async with database.transaction() as repositories:
                    await repositories.jobs.complete(
                        result,
                        owner="worker:t06-other",
                        fencing_token=token,
                    )

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


def test_only_exhaustion_settlement_lease_owner_can_fail_job(
    result_database_url: str,
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(result_database_url))
        job_id = "job:t06-exhaustion-owner"
        failure = StructuredFailure(
            code="worker.attempts_exhausted",
            kind=FailureKind.TOOL,
            message="job execution attempts were exhausted",
            retryable=False,
            details={"attempt": 1},
        )
        result = WorkerResult(
            schema_version=SchemaVersion.VALUE_1_0_0,
            job_id=job_id,
            status=JobStatus.FAILED,
            produced_artifact_version_ids=[],
            evidence_ids=[],
            failure=failure,
        )
        try:
            first_token = await _enqueue_and_claim(
                database, job_id, "worker:t06-old", max_attempts=1
            )
            async with database.engine.begin() as connection:
                await connection.execute(
                    update(jobs)
                    .where(jobs.c.id == job_id)
                    .values(
                        lease={
                            "owner": "worker:t06-old",
                            "fencing_token": first_token,
                            "expires_at": datetime(2020, 1, 1, tzinfo=UTC).isoformat(),
                            "heartbeat_interval_seconds": 10,
                        }
                    )
                )
            async with database.transaction() as repositories:
                settlement = await repositories.jobs.claim_lease(
                    job_id,
                    owner="worker:t06-settler",
                    lease_seconds=60,
                    heartbeat_interval_seconds=10,
                )
            assert settlement.job["lease"] is not None
            settlement_token = settlement.job["lease"]["fencing_token"]
            with pytest.raises(JobLeaseConflict):
                async with database.transaction() as repositories:
                    await repositories.jobs.fail_exhausted(
                        result,
                        owner="worker:t06-old",
                        fencing_token=first_token,
                    )
            async with database.transaction() as repositories:
                completed = await repositories.jobs.fail_exhausted(
                    result,
                    owner="worker:t06-settler",
                    fencing_token=settlement_token,
                )
            assert completed.job["status"] is JobStatus.FAILED
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
                        fencing_token="missing-job",
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
            token = await _enqueue_and_claim(database, job_id, "worker:t06-a")
            async with database.transaction() as repositories:
                released = await repositories.jobs.record_attempt_failure(
                    job_id,
                    attempt=1,
                    owner="worker:t06-a",
                    fencing_token=token,
                    failure=failure,
                )
            assert released["status"] is JobStatus.QUEUED
            assert released["lease"] is None

            async with database.transaction() as repositories:
                repeated = await repositories.jobs.record_attempt_failure(
                    job_id,
                    attempt=1,
                    owner="worker:t06-a",
                    fencing_token=token,
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
                        fencing_token=token,
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
            token = await _enqueue_and_claim(
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
                        fencing_token=token,
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


def test_retry_cannot_be_claimed_before_database_backoff_expires(
    result_database_url: str,
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(result_database_url))
        job_id = "job:t06-attempt-backoff"
        failure = StructuredFailure(
            code="test.retryable",
            kind=FailureKind.TOOL,
            message="safe retryable failure",
            retryable=True,
            details={},
        )
        try:
            token = await _enqueue_and_claim(
                database,
                job_id,
                "worker:t06-a",
                backoff_seconds=0.1,
            )
            async with database.transaction() as repositories:
                await repositories.jobs.record_attempt_failure(
                    job_id,
                    attempt=1,
                    owner="worker:t06-a",
                    fencing_token=token,
                    failure=failure,
                )
            async with database.transaction() as repositories:
                backing_off = await repositories.jobs.claim_lease(
                    job_id,
                    owner="worker:t06-b",
                    lease_seconds=60,
                    heartbeat_interval_seconds=10,
                )
            assert backing_off.outcome is JobLeaseClaimOutcome.BACKING_OFF
            assert 0 < backing_off.retry_after_seconds <= 0.1

            await asyncio.sleep(0.12)
            async with database.transaction() as repositories:
                acquired = await repositories.jobs.claim_lease(
                    job_id,
                    owner="worker:t06-b",
                    lease_seconds=60,
                    heartbeat_interval_seconds=10,
                )
            assert acquired.outcome is JobLeaseClaimOutcome.ACQUIRED
            assert acquired.job["attempt"] == 2
        finally:
            await database.dispose()

    asyncio.run(scenario())
