from __future__ import annotations

import asyncio
import sys
from dataclasses import replace
from datetime import UTC, datetime

import pytest
from redis.asyncio import Redis
from sqlalchemy import update
from vulnweaver_contracts import (
    FailureKind,
    Job,
    JobStatus,
    SchemaVersion,
    StructuredFailure,
    WorkerResult,
)
from vulnweaver_persistence import Database, DatabaseSettings
from vulnweaver_persistence.models import jobs
from vulnweaver_queue import (
    DeadLetteredMessage,
    QueueSettings,
    RedisStreamsClient,
    StreamMessage,
)
from vulnweaver_worker import ReliableWorker, WorkerSettings

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
def worker_database_url(persistence_database_url: str) -> str:
    async def seed() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        try:
            async with database.transaction() as repositories:
                await repositories.projects.add(project("project:t06-worker"))
                await repositories.artifacts.add(
                    artifact(
                        "artifact:t06-worker",
                        project_id="project:t06-worker",
                        current_version_id="artifact-version:t06-worker",
                    )
                )
                await repositories.artifacts.add_version(
                    artifact_version(
                        "artifact-version:t06-worker",
                        artifact_id="artifact:t06-worker",
                    )
                )
                await repositories.tasks.create(
                    task(
                        "task:t06-worker",
                        project_id="project:t06-worker",
                        artifact_version_ids=["artifact-version:t06-worker"],
                        idempotency_key="task:t06-worker-key",
                    )
                )
        finally:
            await database.dispose()

    asyncio.run(seed())
    return persistence_database_url


def _success(job_id: str) -> WorkerResult:
    return WorkerResult(
        schema_version=SchemaVersion.VALUE_1_0_0,
        job_id=job_id,
        status=JobStatus.SUCCEEDED,
        produced_artifact_version_ids=[],
        evidence_ids=[],
        failure=None,
    )


def _retryable_failure(job_id: str) -> WorkerResult:
    return WorkerResult(
        schema_version=SchemaVersion.VALUE_1_0_0,
        job_id=job_id,
        status=JobStatus.FAILED,
        produced_artifact_version_ids=[],
        evidence_ids=[],
        failure=StructuredFailure(
            code="test.retryable",
            kind=FailureKind.TOOL,
            message="safe test failure",
            retryable=True,
            details={},
        ),
    )


class SuccessExecutor:
    def __init__(self, *, delay_seconds: float = 0) -> None:
        self.calls = 0
        self.delay_seconds = delay_seconds

    async def execute(self, value: Job, cancellation: asyncio.Event) -> WorkerResult:
        self.calls += 1
        if self.delay_seconds:
            await asyncio.sleep(self.delay_seconds)
        return _success(value["id"])


class RetryThenSucceedExecutor:
    def __init__(self, *, always_fail: bool = False) -> None:
        self.calls = 0
        self.always_fail = always_fail

    async def execute(self, value: Job, cancellation: asyncio.Event) -> WorkerResult:
        self.calls += 1
        if self.calls == 1 or self.always_fail:
            return _retryable_failure(value["id"])
        return _success(value["id"])


class CooperativeExecutor:
    def __init__(self) -> None:
        self.started = asyncio.Event()

    async def execute(self, value: Job, cancellation: asyncio.Event) -> WorkerResult:
        self.started.set()
        await cancellation.wait()
        return WorkerResult(
            schema_version=SchemaVersion.VALUE_1_0_0,
            job_id=value["id"],
            status=JobStatus.CANCELLED,
            produced_artifact_version_ids=[],
            evidence_ids=[],
            failure=None,
        )


class UncooperativeExecutor:
    def __init__(self) -> None:
        self.started = asyncio.Event()

    async def execute(self, value: Job, cancellation: asyncio.Event) -> WorkerResult:
        self.started.set()
        await asyncio.Event().wait()
        raise AssertionError("unreachable")


class FlakyAckQueue(RedisStreamsClient):
    def __init__(self, settings: QueueSettings) -> None:
        super().__init__(settings)
        self.acknowledgements = 0

    async def acknowledge(self, stream: str, group: str, message_id: str) -> bool:
        self.acknowledgements += 1
        if self.acknowledgements == 1:
            raise ConnectionError("simulated ACK loss")
        return await super().acknowledge(stream, group, message_id)


class FlakyDeadLetterQueue(RedisStreamsClient):
    def __init__(self, settings: QueueSettings) -> None:
        super().__init__(settings)
        self.dead_letters = 0

    async def dead_letter(
        self,
        stream: str,
        group: str,
        message: StreamMessage,
        *,
        failure: StructuredFailure,
        attempt: int,
    ) -> DeadLetteredMessage:
        self.dead_letters += 1
        if self.dead_letters == 1:
            raise ConnectionError("simulated dead-letter write loss")
        return await super().dead_letter(
            stream,
            group,
            message,
            failure=failure,
            attempt=attempt,
        )


async def _enqueue(database: Database, queue: RedisStreamsClient, job_id: str) -> None:
    value = job(
        job_id,
        task_id="task:t06-worker",
        idempotency_key=f"{job_id}-key",
    )
    event = job_event(value, f"event:{job_id}")
    async with database.transaction() as repositories:
        await repositories.jobs.enqueue_with_outbox(value, event)
    await queue.publish(event)


async def _wait_for_status(
    database: Database, job_id: str, status: JobStatus, *, timeout: float = 5
) -> Job:
    async def wait() -> Job:
        while True:
            async with database.transaction() as repositories:
                stored = await repositories.jobs.get(job_id)
            if stored["status"] is status:
                return stored
            await asyncio.sleep(0.01)

    return await asyncio.wait_for(wait(), timeout)


def _settings(namespace: str) -> QueueSettings:
    return QueueSettings("redis://127.0.0.1:6379/15", namespace=namespace)


def _worker_settings(name: str) -> WorkerSettings:
    return WorkerSettings(
        consumer_name=name,
        read_block_milliseconds=10,
        pending_idle_milliseconds=10,
        lease_seconds=3,
        heartbeat_interval_seconds=1,
        shutdown_grace_seconds=1,
    )


def test_worker_persists_success_before_ack_and_renews_lease(
    worker_database_url: str, redis_url: str, redis_namespace: str
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(worker_database_url))
        queue = RedisStreamsClient(QueueSettings(redis_url, namespace=redis_namespace))
        raw = Redis.from_url(redis_url, decode_responses=True)
        executor = SuccessExecutor(delay_seconds=1.1)
        stop = asyncio.Event()
        worker = ReliableWorker(database, queue, executor, _worker_settings("worker-success"))
        try:
            await _enqueue(database, queue, "job:t06-worker-success")
            running = asyncio.create_task(worker.run(stop))
            stored = await _wait_for_status(database, "job:t06-worker-success", JobStatus.SUCCEEDED)
            stop.set()
            await asyncio.wait_for(running, 2)
            assert executor.calls == 1
            assert stored["lease"] is None
            assert (await raw.xpending(queue.streams.jobs, "workers"))["pending"] == 0
        finally:
            await raw.aclose()
            await queue.close()
            await database.dispose()

    asyncio.run(scenario())


def test_ack_loss_replays_without_executing_job_twice(
    worker_database_url: str, redis_url: str, redis_namespace: str
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(worker_database_url))
        queue = FlakyAckQueue(QueueSettings(redis_url, namespace=redis_namespace))
        raw = Redis.from_url(redis_url, decode_responses=True)
        executor = SuccessExecutor()
        stop = asyncio.Event()
        worker = ReliableWorker(database, queue, executor, _worker_settings("worker-ack-loss"))
        try:
            await _enqueue(database, queue, "job:t06-worker-ack-loss")
            running = asyncio.create_task(worker.run(stop))
            await _wait_for_status(database, "job:t06-worker-ack-loss", JobStatus.SUCCEEDED)

            async def acknowledged() -> None:
                while (await raw.xpending(queue.streams.jobs, "workers"))["pending"]:
                    await asyncio.sleep(0.01)

            await asyncio.wait_for(acknowledged(), 3)
            stop.set()
            await asyncio.wait_for(running, 2)
            assert executor.calls == 1
            assert queue.acknowledgements == 2
        finally:
            await raw.aclose()
            await queue.close()
            await database.dispose()

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("always_fail", "expected_status", "expected_calls", "dead_letter_count"),
    [
        (False, JobStatus.SUCCEEDED, 2, 0),
        (True, JobStatus.FAILED, 2, 1),
    ],
)
def test_retryable_failure_retries_then_succeeds_or_dead_letters(
    worker_database_url: str,
    redis_url: str,
    redis_namespace: str,
    always_fail: bool,
    expected_status: JobStatus,
    expected_calls: int,
    dead_letter_count: int,
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(worker_database_url))
        queue = RedisStreamsClient(QueueSettings(redis_url, namespace=redis_namespace))
        raw = Redis.from_url(redis_url, decode_responses=True)
        executor = RetryThenSucceedExecutor(always_fail=always_fail)
        stop = asyncio.Event()
        suffix = "exhausted" if always_fail else "retry-success"
        worker = ReliableWorker(database, queue, executor, _worker_settings(f"worker-{suffix}"))
        try:
            await _enqueue(database, queue, f"job:t06-worker-{suffix}")
            running = asyncio.create_task(worker.run(stop))
            stored = await _wait_for_status(database, f"job:t06-worker-{suffix}", expected_status)
            stop.set()
            await asyncio.wait_for(running, 2)
            assert executor.calls == expected_calls
            assert stored["attempt"] == 2
            assert await raw.xlen(queue.streams.dead_letters) == dead_letter_count
        finally:
            await raw.aclose()
            await queue.close()
            await database.dispose()

    asyncio.run(scenario())


def test_graceful_stop_releases_cooperative_execution(
    worker_database_url: str, redis_url: str, redis_namespace: str
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(worker_database_url))
        queue = RedisStreamsClient(QueueSettings(redis_url, namespace=redis_namespace))
        raw = Redis.from_url(redis_url, decode_responses=True)
        executor = CooperativeExecutor()
        stop = asyncio.Event()
        worker = ReliableWorker(database, queue, executor, _worker_settings("worker-stop"))
        try:
            await _enqueue(database, queue, "job:t06-worker-stop")
            running = asyncio.create_task(worker.run(stop))
            await asyncio.wait_for(executor.started.wait(), 2)
            stop.set()
            await asyncio.wait_for(running, 2)
            stored = await _wait_for_status(database, "job:t06-worker-stop", JobStatus.QUEUED)
            assert stored["lease"] is None
            assert (await raw.xpending(queue.streams.jobs, "workers"))["pending"] == 1
        finally:
            await raw.aclose()
            await queue.close()
            await database.dispose()

    asyncio.run(scenario())


def test_shutdown_timeout_cancels_executor_and_releases_lease(
    worker_database_url: str, redis_url: str, redis_namespace: str
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(worker_database_url))
        queue = RedisStreamsClient(QueueSettings(redis_url, namespace=redis_namespace))
        executor = UncooperativeExecutor()
        stop = asyncio.Event()
        settings = replace(_worker_settings("worker-forced-stop"), shutdown_grace_seconds=0.05)
        worker = ReliableWorker(database, queue, executor, settings)
        try:
            await _enqueue(database, queue, "job:t06-worker-forced-stop")
            running = asyncio.create_task(worker.run(stop))
            await asyncio.wait_for(executor.started.wait(), 2)
            stop.set()
            await asyncio.wait_for(running, 2)
            stored = await _wait_for_status(
                database, "job:t06-worker-forced-stop", JobStatus.QUEUED
            )
            assert stored["lease"] is None
        finally:
            await queue.close()
            await database.dispose()

    asyncio.run(scenario())


def test_already_exhausted_job_is_finalized_without_execution(
    worker_database_url: str, redis_url: str, redis_namespace: str
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(worker_database_url))
        queue = RedisStreamsClient(QueueSettings(redis_url, namespace=redis_namespace))
        raw = Redis.from_url(redis_url, decode_responses=True)
        executor = SuccessExecutor()
        stop = asyncio.Event()
        worker = ReliableWorker(database, queue, executor, _worker_settings("worker-pre-exhausted"))
        try:
            job_id = "job:t06-worker-pre-exhausted"
            await _enqueue(database, queue, job_id)
            for owner in ("worker-old-a", "worker-old-b"):
                async with database.transaction() as repositories:
                    await repositories.jobs.claim_lease(
                        job_id,
                        owner=owner,
                        lease_seconds=3,
                        heartbeat_interval_seconds=1,
                    )
                    await repositories.jobs.release_lease(job_id, owner=owner)

            running = asyncio.create_task(worker.run(stop))
            stored = await _wait_for_status(database, job_id, JobStatus.FAILED)
            stop.set()
            await asyncio.wait_for(running, 2)
            assert executor.calls == 0
            assert stored["failure"] is not None
            assert stored["failure"]["code"] == "worker.attempts_exhausted"
            assert await raw.xlen(queue.streams.dead_letters) == 1
        finally:
            await raw.aclose()
            await queue.close()
            await database.dispose()

    asyncio.run(scenario())


def test_dead_letter_write_loss_recovers_from_persisted_failure(
    worker_database_url: str, redis_url: str, redis_namespace: str
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(worker_database_url))
        queue = FlakyDeadLetterQueue(QueueSettings(redis_url, namespace=redis_namespace))
        raw = Redis.from_url(redis_url, decode_responses=True)
        executor = RetryThenSucceedExecutor(always_fail=True)
        stop = asyncio.Event()
        worker = ReliableWorker(
            database, queue, executor, _worker_settings("worker-dead-letter-loss")
        )
        try:
            job_id = "job:t06-worker-dead-letter-loss"
            await _enqueue(database, queue, job_id)
            running = asyncio.create_task(worker.run(stop))
            await _wait_for_status(database, job_id, JobStatus.FAILED)

            async def dead_lettered() -> None:
                while await raw.xlen(queue.streams.dead_letters) == 0:
                    await asyncio.sleep(0.01)

            await asyncio.wait_for(dead_lettered(), 3)
            stop.set()
            await asyncio.wait_for(running, 2)
            assert executor.calls == 2
            assert queue.dead_letters == 2
            assert (await raw.xpending(queue.streams.jobs, "workers"))["pending"] == 0
        finally:
            await raw.aclose()
            await queue.close()
            await database.dispose()

    asyncio.run(scenario())


def test_stale_message_and_expired_lease_are_taken_over_end_to_end(
    worker_database_url: str, redis_url: str, redis_namespace: str
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(worker_database_url))
        queue = RedisStreamsClient(QueueSettings(redis_url, namespace=redis_namespace))
        raw = Redis.from_url(redis_url, decode_responses=True)
        executor = SuccessExecutor()
        stop = asyncio.Event()
        worker = ReliableWorker(database, queue, executor, _worker_settings("worker-live"))
        try:
            job_id = "job:t06-worker-crash-takeover"
            await _enqueue(database, queue, job_id)
            await queue.ensure_group(queue.streams.jobs, "workers")
            delivered = await queue.read_group(
                queue.streams.jobs,
                "workers",
                "worker-crashed",
                block_milliseconds=10,
            )
            assert len(delivered) == 1
            async with database.transaction() as repositories:
                await repositories.jobs.claim_lease(
                    job_id,
                    owner="worker-crashed",
                    lease_seconds=3,
                    heartbeat_interval_seconds=1,
                )
            async with database.engine.begin() as connection:
                await connection.execute(
                    update(jobs)
                    .where(jobs.c.id == job_id)
                    .values(
                        lease={
                            "owner": "worker-crashed",
                            "expires_at": datetime(2020, 1, 1, tzinfo=UTC).isoformat(),
                            "heartbeat_interval_seconds": 1,
                        }
                    )
                )
            await asyncio.sleep(0.02)

            running = asyncio.create_task(worker.run(stop))
            stored = await _wait_for_status(database, job_id, JobStatus.SUCCEEDED)
            stop.set()
            await asyncio.wait_for(running, 2)
            assert executor.calls == 1
            assert stored["attempt"] == 2
            assert (await raw.xpending(queue.streams.jobs, "workers"))["pending"] == 0
        finally:
            await raw.aclose()
            await queue.close()
            await database.dispose()

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "overrides",
    [
        {"consumer_name": ""},
        {"consumer_name": "worker", "concurrency": 0},
        {"consumer_name": "worker", "concurrency": 129},
        {"consumer_name": "worker", "read_block_milliseconds": 0},
        {"consumer_name": "worker", "read_block_milliseconds": 60_001},
        {"consumer_name": "worker", "pending_idle_milliseconds": 0},
        {"consumer_name": "worker", "heartbeat_interval_seconds": 0},
        {
            "consumer_name": "worker",
            "lease_seconds": 10,
            "heartbeat_interval_seconds": 10,
        },
        {"consumer_name": "worker", "shutdown_grace_seconds": 0},
    ],
)
def test_worker_settings_reject_unsafe_bounds(overrides: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        WorkerSettings(**overrides)  # type: ignore[arg-type]
