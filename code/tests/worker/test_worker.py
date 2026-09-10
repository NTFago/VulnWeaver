from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import UTC, datetime
from typing import cast

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
from vulnweaver_persistence.errors import JobLeaseConflict, PersistenceInvariantError
from vulnweaver_persistence.models import jobs
from vulnweaver_persistence.repositories import JobRepository
from vulnweaver_queue import (
    DeadLetteredMessage,
    QueueSettings,
    QueueUnavailable,
    RedisStreamsClient,
    StaleClaimBatch,
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
        self.call_times: list[float] = []
        self.always_fail = always_fail

    async def execute(self, value: Job, cancellation: asyncio.Event) -> WorkerResult:
        self.calls += 1
        self.call_times.append(asyncio.get_running_loop().time())
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


class BlockingExecutor:
    def __init__(self) -> None:
        self.calls = 0
        self.started = asyncio.Event()
        self.release = asyncio.Event()

    async def execute(self, value: Job, cancellation: asyncio.Event) -> WorkerResult:
        self.calls += 1
        self.started.set()
        await self.release.wait()
        return _success(value["id"])


class GateExecutor:
    def __init__(self, gate: asyncio.Event) -> None:
        self.gate = gate

    async def execute(self, value: Job, cancellation: asyncio.Event) -> WorkerResult:
        await self.gate.wait()
        return _success(value["id"])


class SimultaneousHeartbeatWorker(ReliableWorker):
    gate: asyncio.Event

    async def _heartbeat(self, job_id: str, fencing_token: str) -> None:
        await self.gate.wait()


class SimultaneousHeartbeatFailureWorker(SimultaneousHeartbeatWorker):
    async def _heartbeat(self, job_id: str, fencing_token: str) -> None:
        await self.gate.wait()
        raise JobLeaseConflict("simulated lease loss")


class SettlementTrackingWorker(ReliableWorker):
    recovered = False

    async def _recover_settlement(
        self,
        message: StreamMessage,
        error: JobLeaseConflict | PersistenceInvariantError,
    ) -> None:
        self.recovered = True
        await super()._recover_settlement(message, error)


class CursorTrackingQueue(RedisStreamsClient):
    def __init__(self, settings: QueueSettings, stop: asyncio.Event) -> None:
        super().__init__(settings)
        self.stop = stop
        self.start_ids: list[str] = []
        self.read_blocks: list[int | None] = []

    async def ensure_group(self, stream: str, group: str, *, start_id: str = "0-0") -> None:
        return None

    async def claim_stale(
        self,
        stream: str,
        group: str,
        consumer: str,
        *,
        min_idle_milliseconds: int,
        count: int = 10,
        start_id: str = "0-0",
    ) -> StaleClaimBatch:
        self.start_ids.append(start_id)
        if len(self.start_ids) == 2:
            self.stop.set()
            return StaleClaimBatch("0-0", ())
        return StaleClaimBatch("42-0", ())

    async def read_group(
        self,
        stream: str,
        group: str,
        consumer: str,
        *,
        count: int = 10,
        block_milliseconds: int | None = 1000,
    ) -> list[StreamMessage]:
        self.read_blocks.append(block_milliseconds)
        return []


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


async def _enqueue(
    database: Database,
    queue: RedisStreamsClient,
    job_id: str,
    *,
    retryable_failure_kinds: list[FailureKind] | None = None,
    backoff_seconds: float = 0,
    max_attempts: int = 2,
) -> None:
    value = job(
        job_id,
        task_id="task:t06-worker",
        idempotency_key=f"{job_id}-key",
    )
    value["retry_policy"]["retryable_failure_kinds"] = retryable_failure_kinds or []
    value["retry_policy"]["backoff_seconds"] = backoff_seconds
    value["retry_policy"]["max_attempts"] = max_attempts
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
            await _enqueue(
                database,
                queue,
                f"job:t06-worker-{suffix}",
                retryable_failure_kinds=[FailureKind.TOOL],
            )
            running = asyncio.create_task(worker.run(stop))
            stored = await _wait_for_status(database, f"job:t06-worker-{suffix}", expected_status)
            stop.set()
            await asyncio.wait_for(running, 2)
            assert executor.calls == expected_calls
            assert stored["attempt"] == 2
            assert await raw.xlen(queue.streams.dead_letters) == dead_letter_count
            async with database.transaction() as repositories:
                history = await repositories.jobs.attempt_failures(f"job:t06-worker-{suffix}")
            assert len(history) == 1
            assert history[0].attempt == 1
            assert history[0].failure["code"] == "test.retryable"
        finally:
            await raw.aclose()
            await queue.close()
            await database.dispose()

    asyncio.run(scenario())


def test_retry_policy_backoff_paces_the_next_attempt(
    worker_database_url: str, redis_url: str, redis_namespace: str
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(worker_database_url))
        queue = RedisStreamsClient(QueueSettings(redis_url, namespace=redis_namespace))
        executor = RetryThenSucceedExecutor()
        stop = asyncio.Event()
        worker = ReliableWorker(database, queue, executor, _worker_settings("worker-backoff"))
        try:
            job_id = "job:t06-worker-backoff"
            await _enqueue(
                database,
                queue,
                job_id,
                retryable_failure_kinds=[FailureKind.TOOL],
                backoff_seconds=0.2,
            )
            running = asyncio.create_task(worker.run(stop))
            await _wait_for_status(database, job_id, JobStatus.SUCCEEDED)
            stop.set()
            await asyncio.wait_for(running, 2)
            assert executor.calls == 2
            assert executor.call_times[1] - executor.call_times[0] >= 0.18
        finally:
            await queue.close()
            await database.dispose()

    asyncio.run(scenario())


def test_transient_heartbeat_database_error_is_retried(
    worker_database_url: str,
    redis_url: str,
    redis_namespace: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = JobRepository.renew_lease
    renew_calls = 0

    async def flaky_renew(
        repository: JobRepository,
        job_id: str,
        *,
        owner: str,
        fencing_token: str,
        lease_seconds: int,
    ) -> Job:
        nonlocal renew_calls
        renew_calls += 1
        if renew_calls == 1:
            raise ConnectionError("simulated transient database failure")
        return await original(
            repository,
            job_id,
            owner=owner,
            fencing_token=fencing_token,
            lease_seconds=lease_seconds,
        )

    monkeypatch.setattr(JobRepository, "renew_lease", flaky_renew)

    async def scenario() -> None:
        database = Database(DatabaseSettings(worker_database_url))
        queue = RedisStreamsClient(QueueSettings(redis_url, namespace=redis_namespace))
        executor = SuccessExecutor(delay_seconds=1.7)
        stop = asyncio.Event()
        worker = ReliableWorker(
            database, queue, executor, _worker_settings("worker-heartbeat-retry")
        )
        try:
            job_id = "job:t06-worker-heartbeat-retry"
            await _enqueue(database, queue, job_id)
            running = asyncio.create_task(worker.run(stop))
            await _wait_for_status(database, job_id, JobStatus.SUCCEEDED)
            stop.set()
            await asyncio.wait_for(running, 2)
            assert executor.calls == 1
            assert renew_calls >= 2
        finally:
            await queue.close()
            await database.dispose()

    asyncio.run(scenario())


def test_retryable_flag_does_not_override_empty_retry_kind_allowlist(
    worker_database_url: str, redis_url: str, redis_namespace: str
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(worker_database_url))
        queue = RedisStreamsClient(QueueSettings(redis_url, namespace=redis_namespace))
        executor = RetryThenSucceedExecutor()
        stop = asyncio.Event()
        worker = ReliableWorker(
            database, queue, executor, _worker_settings("worker-empty-retry-policy")
        )
        try:
            job_id = "job:t06-worker-empty-retry-policy"
            await _enqueue(database, queue, job_id)
            running = asyncio.create_task(worker.run(stop))
            stored = await _wait_for_status(database, job_id, JobStatus.FAILED)
            stop.set()
            await asyncio.wait_for(running, 2)
            assert executor.calls == 1
            assert stored["attempt"] == 1
            async with database.transaction() as repositories:
                history = await repositories.jobs.attempt_failures(job_id)
            assert history == []
        finally:
            await queue.close()
            await database.dispose()

    asyncio.run(scenario())


def test_same_owner_reclaim_does_not_start_a_second_execution(
    worker_database_url: str, redis_url: str, redis_namespace: str
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(worker_database_url))
        queue = RedisStreamsClient(QueueSettings(redis_url, namespace=redis_namespace))
        executor = BlockingExecutor()
        stop = asyncio.Event()
        worker = ReliableWorker(database, queue, executor, _worker_settings("worker-owner-a"))
        first_processing: asyncio.Task[None] | None = None
        repeated_processing: asyncio.Task[None] | None = None
        try:
            job_id = "job:t06-worker-same-owner-reclaim"
            await _enqueue(database, queue, job_id)
            await queue.ensure_group(queue.streams.jobs, "workers")
            delivered = await queue.read_group(
                queue.streams.jobs,
                "workers",
                "worker-owner-a",
                block_milliseconds=10,
            )
            first_processing = asyncio.create_task(worker._process(delivered[0], stop))
            await asyncio.wait_for(executor.started.wait(), 2)

            await asyncio.sleep(0.01)
            claimed_by_b = await queue.claim_stale(
                queue.streams.jobs,
                "workers",
                "worker-owner-b",
                min_idle_milliseconds=1,
            )
            assert len(claimed_by_b.messages) == 1
            await asyncio.sleep(0.01)
            claimed_back_by_a = await queue.claim_stale(
                queue.streams.jobs,
                "workers",
                "worker-owner-a",
                min_idle_milliseconds=1,
            )
            assert len(claimed_back_by_a.messages) == 1
            repeated_processing = asyncio.create_task(
                worker._process(claimed_back_by_a.messages[0], stop)
            )
            await asyncio.sleep(0.05)
            assert executor.calls == 1
        finally:
            executor.release.set()
            tasks = [item for item in (first_processing, repeated_processing) if item is not None]
            if tasks:
                await asyncio.gather(*tasks)
            await queue.close()
            await database.dispose()

    asyncio.run(scenario())


def test_executor_result_wins_when_heartbeat_completes_in_same_tick(
    worker_database_url: str, redis_url: str, redis_namespace: str
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(worker_database_url))
        queue = RedisStreamsClient(QueueSettings(redis_url, namespace=redis_namespace))
        gate = asyncio.Event()
        worker = SimultaneousHeartbeatWorker(
            database,
            queue,
            GateExecutor(gate),
            _worker_settings("worker-simultaneous"),
        )
        worker.gate = gate
        try:
            execution = asyncio.create_task(
                worker._execute_with_heartbeat(
                    job(
                        "job:t06-simultaneous",
                        task_id="task:t06-worker",
                        idempotency_key="job:t06-simultaneous-key",
                    ),
                    asyncio.Event(),
                    fencing_token="test-fencing-token",
                )
            )
            await asyncio.sleep(0)
            gate.set()
            result = await asyncio.wait_for(execution, 2)
            assert result["status"] is JobStatus.SUCCEEDED
        finally:
            await queue.close()
            await database.dispose()

    asyncio.run(scenario())


def test_heartbeat_lease_failure_wins_when_execution_finishes_in_same_tick(
    worker_database_url: str, redis_url: str, redis_namespace: str
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(worker_database_url))
        queue = RedisStreamsClient(QueueSettings(redis_url, namespace=redis_namespace))
        gate = asyncio.Event()
        worker = SimultaneousHeartbeatFailureWorker(
            database,
            queue,
            GateExecutor(gate),
            _worker_settings("worker-simultaneous-failure"),
        )
        worker.gate = gate
        try:
            execution = asyncio.create_task(
                worker._execute_with_heartbeat(
                    job(
                        "job:t06-simultaneous-failure",
                        task_id="task:t06-worker",
                        idempotency_key="job:t06-simultaneous-failure-key",
                    ),
                    asyncio.Event(),
                    fencing_token="test-fencing-token",
                )
            )
            await asyncio.sleep(0)
            gate.set()
            with pytest.raises(Exception) as captured:
                await asyncio.wait_for(execution, 2)
            assert isinstance(captured.value.__cause__, JobLeaseConflict)
        finally:
            await queue.close()
            await database.dispose()

    asyncio.run(scenario())


class FlakyReadQueue(RedisStreamsClient):
    """Fail the first ``failures`` reads with a transient Redis stall, then stop the loop."""

    def __init__(self, settings: QueueSettings, stop: asyncio.Event, *, failures: int) -> None:
        super().__init__(settings)
        self.stop = stop
        self.failures = failures
        self.read_calls = 0

    async def ensure_group(self, stream: str, group: str, *, start_id: str = "0-0") -> None:
        del stream, group, start_id

    async def claim_stale(
        self,
        stream: str,
        group: str,
        consumer: str,
        *,
        min_idle_milliseconds: int,
        count: int = 10,
        start_id: str = "0-0",
    ) -> StaleClaimBatch:
        del stream, group, consumer, min_idle_milliseconds, count, start_id
        return StaleClaimBatch("0-0", ())

    async def read_group(
        self,
        stream: str,
        group: str,
        consumer: str,
        *,
        count: int = 10,
        block_milliseconds: int | None = 1000,
    ) -> list[StreamMessage]:
        del stream, group, consumer, count, block_milliseconds
        self.read_calls += 1
        if self.failures > 0:
            self.failures -= 1
            raise QueueUnavailable(
                "Redis operation failed", details={"operation": "read_group"}
            )
        self.stop.set()
        return []


def test_transient_queue_failure_keeps_the_worker_consuming() -> None:
    """A Redis stall must not end the consumer; the loop backs off and resumes polling."""

    async def scenario() -> None:
        stop = asyncio.Event()
        queue = FlakyReadQueue(_settings("worker-flaky"), stop, failures=2)
        worker = ReliableWorker(
            # No message is ever claimed, so the consume loop never touches the database.
            cast(Database, None),
            queue,
            SuccessExecutor(),
            replace(
                _worker_settings("worker-flaky"),
                retry_base_seconds=0.01,
                retry_max_seconds=0.02,
            ),
        )
        try:
            await asyncio.wait_for(worker.run(stop), 5)
            assert queue.failures == 0
            assert queue.read_calls >= 3
        finally:
            await queue.close()

    asyncio.run(scenario())


def test_stale_claim_cursor_advances_between_scans(
    worker_database_url: str, redis_url: str, redis_namespace: str
) -> None:
    async def scenario() -> None:
        stop = asyncio.Event()
        database = Database(DatabaseSettings(worker_database_url))
        queue = CursorTrackingQueue(QueueSettings(redis_url, namespace=redis_namespace), stop)
        worker = ReliableWorker(
            database, queue, SuccessExecutor(), _worker_settings("worker-cursor")
        )
        try:
            await asyncio.wait_for(worker.run(stop), 2)
            assert queue.start_ids == ["0-0", "42-0"]
            assert None in queue.read_blocks
            assert worker._settings.read_block_milliseconds in queue.read_blocks
        finally:
            await queue.close()
            await database.dispose()

    asyncio.run(scenario())


def test_waiting_permission_message_remains_pending_and_resumes(
    worker_database_url: str, redis_url: str, redis_namespace: str
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(worker_database_url))
        queue = RedisStreamsClient(QueueSettings(redis_url, namespace=redis_namespace))
        raw = Redis.from_url(redis_url, decode_responses=True)
        executor = SuccessExecutor()
        first_stop = asyncio.Event()
        first_worker = ReliableWorker(
            database, queue, executor, _worker_settings("worker-permission-wait")
        )
        try:
            job_id = "job:t06-worker-permission-wait"
            await _enqueue(database, queue, job_id)
            async with database.engine.begin() as connection:
                await connection.execute(
                    update(jobs)
                    .where(jobs.c.id == job_id)
                    .values(status=JobStatus.WAITING_PERMISSION.value)
                )
            first_running = asyncio.create_task(first_worker.run(first_stop))

            async def pending() -> None:
                while (await raw.xpending(queue.streams.jobs, "workers"))["pending"] != 1:
                    await asyncio.sleep(0.01)

            await asyncio.wait_for(pending(), 2)
            await asyncio.sleep(0.05)
            first_stop.set()
            await asyncio.wait_for(first_running, 2)
            assert executor.calls == 0
            assert (await raw.xpending(queue.streams.jobs, "workers"))["pending"] == 1

            async with database.engine.begin() as connection:
                await connection.execute(
                    update(jobs).where(jobs.c.id == job_id).values(status=JobStatus.QUEUED.value)
                )
            await asyncio.sleep(0.02)
            resumed_stop = asyncio.Event()
            resumed = ReliableWorker(
                database, queue, executor, _worker_settings("worker-permission-resumed")
            )
            resumed_running = asyncio.create_task(resumed.run(resumed_stop))
            await _wait_for_status(database, job_id, JobStatus.SUCCEEDED)
            resumed_stop.set()
            await asyncio.wait_for(resumed_running, 2)
            assert executor.calls == 1
            assert (await raw.xpending(queue.streams.jobs, "workers"))["pending"] == 0
        finally:
            await raw.aclose()
            await queue.close()
            await database.dispose()

    asyncio.run(scenario())


def test_settlement_invariant_is_reconciled_without_acking_runnable_job(
    worker_database_url: str,
    redis_url: str,
    redis_namespace: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def reject_completion(
        repository: JobRepository,
        result: WorkerResult,
        *,
        owner: str,
        fencing_token: str,
    ) -> object:
        raise PersistenceInvariantError("simulated concurrent state transition")

    monkeypatch.setattr(JobRepository, "complete", reject_completion)

    async def scenario() -> None:
        database = Database(DatabaseSettings(worker_database_url))
        queue = RedisStreamsClient(QueueSettings(redis_url, namespace=redis_namespace))
        raw = Redis.from_url(redis_url, decode_responses=True)
        worker = SettlementTrackingWorker(
            database, queue, SuccessExecutor(), _worker_settings("worker-settlement-recovery")
        )
        try:
            job_id = "job:t06-worker-settlement-recovery"
            await _enqueue(database, queue, job_id)
            await queue.ensure_group(queue.streams.jobs, "workers")
            delivered = await queue.read_group(
                queue.streams.jobs,
                "workers",
                "worker-settlement-recovery",
                block_milliseconds=10,
            )
            await worker._process(delivered[0], asyncio.Event())
            assert worker.recovered
            assert (await raw.xpending(queue.streams.jobs, "workers"))["pending"] == 1
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
            await _enqueue(
                database,
                queue,
                "job:t06-worker-stop",
                max_attempts=1,
            )
            running = asyncio.create_task(worker.run(stop))
            await asyncio.wait_for(executor.started.wait(), 2)
            stop.set()
            await asyncio.wait_for(running, 2)
            stored = await _wait_for_status(database, "job:t06-worker-stop", JobStatus.QUEUED)
            assert stored["lease"] is None
            assert stored["attempt"] == 0
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
                    old_claim = await repositories.jobs.claim_lease(
                        job_id,
                        owner=owner,
                        lease_seconds=3,
                        heartbeat_interval_seconds=1,
                    )
                assert old_claim.job["lease"] is not None
                expired_lease = dict(old_claim.job["lease"])
                expired_lease["expires_at"] = datetime(2020, 1, 1, tzinfo=UTC).isoformat()
                async with database.engine.begin() as connection:
                    await connection.execute(
                        update(jobs).where(jobs.c.id == job_id).values(lease=expired_lease)
                    )

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
            assert executor.calls == 1
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
                            "fencing_token": "crashed-worker-token",
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
