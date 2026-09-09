"""Consumer-group, database lease and terminal result orchestration."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Protocol

from vulnweaver_contracts import (
    FailureKind,
    Job,
    JobStatus,
    SchemaVersion,
    StructuredFailure,
    WorkerResult,
)
from vulnweaver_persistence import (
    Database,
    JobLeaseClaim,
    JobLeaseClaimOutcome,
    JobLeaseConflict,
    PersistenceInvariantError,
    Repositories,
)
from vulnweaver_queue import RedisStreamsClient, StreamMessage

LOGGER = logging.getLogger("vulnweaver.worker")


class JobExecutor(Protocol):
    async def execute(self, job: Job, cancellation: asyncio.Event) -> WorkerResult: ...


class JobSettlementHook(Protocol):
    async def after_terminal(
        self, repositories: Repositories, job: Job, result: WorkerResult
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class WorkerSettings:
    consumer_name: str
    consumer_group: str = "workers"
    concurrency: int = 1
    read_block_milliseconds: int = 1000
    pending_idle_milliseconds: int = 30_000
    lease_seconds: int = 30
    heartbeat_interval_seconds: int = 10
    shutdown_grace_seconds: float = 30.0

    def __post_init__(self) -> None:
        if not self.consumer_name:
            raise ValueError("worker consumer name is required")
        if self.concurrency < 1 or self.concurrency > 128:
            raise ValueError("worker concurrency must be between 1 and 128")
        if self.read_block_milliseconds < 1 or self.read_block_milliseconds > 60_000:
            raise ValueError("worker read block must be between 1 and 60000 ms")
        if self.pending_idle_milliseconds < 1:
            raise ValueError("worker pending idle duration must be positive")
        if self.heartbeat_interval_seconds < 1:
            raise ValueError("worker heartbeat interval must be positive")
        if self.lease_seconds <= self.heartbeat_interval_seconds:
            raise ValueError("worker lease duration must exceed its heartbeat interval")
        if self.shutdown_grace_seconds <= 0:
            raise ValueError("worker shutdown grace duration must be positive")


class _LeaseHeartbeatFailed(Exception):
    pass


class ReliableWorker:
    def __init__(
        self,
        database: Database,
        queue: RedisStreamsClient,
        executor: JobExecutor,
        settings: WorkerSettings,
        settlement_hook: JobSettlementHook | None = None,
    ) -> None:
        self._database = database
        self._queue = queue
        self._executor = executor
        self._settings = settings
        self._settlement_hook = settlement_hook

    async def run(self, stop: asyncio.Event) -> None:
        """Consume until stopped, then drain or safely release in-flight leases."""

        stream = self._queue.streams.jobs
        await self._queue.ensure_group(stream, self._settings.consumer_group)
        running: set[asyncio.Task[None]] = set()
        stale_cursor = "0-0"
        prefer_fresh = False
        while not stop.is_set():
            running = {task for task in running if not task.done()}
            capacity = self._settings.concurrency - len(running)
            if capacity == 0:
                await asyncio.wait(
                    running,
                    timeout=min(self._settings.heartbeat_interval_seconds, 1),
                    return_when=asyncio.FIRST_COMPLETED,
                )
                continue

            messages: list[StreamMessage] = []
            if prefer_fresh:
                messages.extend(
                    await self._queue.read_group(
                        stream,
                        self._settings.consumer_group,
                        self._settings.consumer_name,
                        count=capacity,
                        block_milliseconds=None,
                    )
                )
            if len(messages) < capacity:
                claimed = await self._queue.claim_stale(
                    stream,
                    self._settings.consumer_group,
                    self._settings.consumer_name,
                    min_idle_milliseconds=self._settings.pending_idle_milliseconds,
                    count=capacity - len(messages),
                    start_id=stale_cursor,
                )
                stale_cursor = claimed.next_start_id
                messages.extend(claimed.messages)
            if not prefer_fresh and len(messages) < capacity:
                messages.extend(
                    await self._queue.read_group(
                        stream,
                        self._settings.consumer_group,
                        self._settings.consumer_name,
                        count=capacity - len(messages),
                        block_milliseconds=None,
                    )
                )
            if not messages:
                messages = await self._queue.read_group(
                    stream,
                    self._settings.consumer_group,
                    self._settings.consumer_name,
                    count=capacity,
                    block_milliseconds=self._settings.read_block_milliseconds,
                )
            prefer_fresh = not prefer_fresh
            for message in messages:
                running.add(asyncio.create_task(self._process(message, stop)))

        await self._drain(running)

    async def _drain(self, running: set[asyncio.Task[None]]) -> None:
        if not running:
            return
        _, pending = await asyncio.wait(running, timeout=self._settings.shutdown_grace_seconds)
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)

    async def _process(self, message: StreamMessage, stop: asyncio.Event) -> None:
        claim: JobLeaseClaim | None = None
        try:
            while not stop.is_set():
                async with self._database.transaction() as repositories:
                    claim = await repositories.jobs.claim_lease(
                        message.event["aggregate_id"],
                        owner=self._settings.consumer_name,
                        lease_seconds=self._settings.lease_seconds,
                        heartbeat_interval_seconds=self._settings.heartbeat_interval_seconds,
                    )
                if claim.outcome in {
                    JobLeaseClaimOutcome.BUSY,
                    JobLeaseClaimOutcome.ALREADY_OWNED,
                }:
                    return
                if claim.outcome is JobLeaseClaimOutcome.BACKING_OFF:
                    if not await self._wait_for_retry(claim.retry_after_seconds, stop):
                        return
                    claim = None
                    continue
                if claim.outcome is JobLeaseClaimOutcome.COMPLETED:
                    await self._acknowledge(message)
                    return
                if claim.outcome is JobLeaseClaimOutcome.EXHAUSTED:
                    fencing_token = _fencing_token(claim.job)
                    try:
                        await self._finalize_exhausted(
                            message, claim.job, fencing_token=fencing_token
                        )
                    except (JobLeaseConflict, PersistenceInvariantError) as error:
                        await self._recover_settlement(message, error)
                    return
                if claim.outcome is JobLeaseClaimOutcome.NOT_RUNNABLE:
                    await self._settle_existing_terminal(message, claim.job)
                    return

                fencing_token = _fencing_token(claim.job)
                try:
                    result = await self._execute_with_heartbeat(
                        claim.job, stop, fencing_token=fencing_token
                    )
                except _LeaseHeartbeatFailed:
                    LOGGER.warning(
                        "worker_lease_heartbeat_failed",
                        extra={"job_id": claim.job["id"]},
                    )
                    return
                except asyncio.CancelledError:
                    raise
                except Exception as error:
                    result = _unexpected_failure_result(claim.job["id"], error)

                if result["job_id"] != claim.job["id"]:
                    result = _unexpected_failure_result(
                        claim.job["id"],
                        ValueError("executor returned a different job identifier"),
                    )
                try:
                    retry_after = await self._settle_execution_result(
                        message,
                        claim.job,
                        result,
                        stop,
                        fencing_token=fencing_token,
                    )
                except (JobLeaseConflict, PersistenceInvariantError) as error:
                    await self._recover_settlement(message, error)
                    return
                if retry_after is None:
                    return
                claim = None
                if not await self._wait_for_retry(retry_after, stop):
                    return
        except asyncio.CancelledError:
            if claim is not None and claim.outcome in {
                JobLeaseClaimOutcome.ACQUIRED,
                JobLeaseClaimOutcome.EXHAUSTED,
            }:
                await asyncio.shield(
                    self._release_if_owned(
                        claim.job["id"],
                        fencing_token=_fencing_token(claim.job),
                        refund_attempt=claim.outcome is JobLeaseClaimOutcome.ACQUIRED,
                    )
                )
            raise
        except Exception:
            LOGGER.exception(
                "worker_message_processing_failed",
                extra={"event_id": message.event["event_id"]},
            )

    async def _execute_with_heartbeat(
        self, job: Job, stop: asyncio.Event, *, fencing_token: str
    ) -> WorkerResult:
        execution = asyncio.create_task(self._executor.execute(job, stop))
        heartbeat = asyncio.create_task(self._heartbeat(job["id"], fencing_token))
        try:
            done, _ = await asyncio.wait(
                {execution, heartbeat}, return_when=asyncio.FIRST_COMPLETED
            )
            if heartbeat in done:
                heartbeat_error = heartbeat.exception()
                if heartbeat_error is not None:
                    if execution in done:
                        await asyncio.gather(execution, return_exceptions=True)
                    raise _LeaseHeartbeatFailed from heartbeat_error
            if execution in done:
                heartbeat.cancel()
                await asyncio.gather(heartbeat, return_exceptions=True)
                return await execution

            if heartbeat in done:
                execution.cancel()
                await asyncio.gather(execution, return_exceptions=True)
                try:
                    await heartbeat
                except Exception as error:
                    raise _LeaseHeartbeatFailed from error
                raise _LeaseHeartbeatFailed

            raise _LeaseHeartbeatFailed
        finally:
            for task in (execution, heartbeat):
                if not task.done():
                    task.cancel()
            await asyncio.gather(execution, heartbeat, return_exceptions=True)

    async def _heartbeat(self, job_id: str, fencing_token: str) -> None:
        loop = asyncio.get_running_loop()
        lease_deadline = loop.time() + self._settings.lease_seconds
        while True:
            await asyncio.sleep(self._settings.heartbeat_interval_seconds)
            while True:
                try:
                    async with self._database.transaction() as repositories:
                        await repositories.jobs.renew_lease(
                            job_id,
                            owner=self._settings.consumer_name,
                            fencing_token=fencing_token,
                            lease_seconds=self._settings.lease_seconds,
                        )
                    lease_deadline = loop.time() + self._settings.lease_seconds
                    break
                except JobLeaseConflict:
                    raise
                except Exception:
                    LOGGER.warning(
                        "worker_lease_heartbeat_retry",
                        extra={"job_id": job_id},
                        exc_info=True,
                    )
                    retry_delay = min(1.0, self._settings.heartbeat_interval_seconds / 2)
                    if loop.time() + retry_delay >= lease_deadline:
                        raise TimeoutError("lease renewal did not recover before expiry") from None
                    await asyncio.sleep(retry_delay)

    async def _settle_execution_result(
        self,
        message: StreamMessage,
        job: Job,
        result: WorkerResult,
        stop: asyncio.Event,
        *,
        fencing_token: str,
    ) -> float | None:
        failure = result["failure"]
        retry_allowed = (
            result["status"] is JobStatus.FAILED
            and failure is not None
            and failure["retryable"]
            and failure["kind"] in job["retry_policy"]["retryable_failure_kinds"]
            and job["attempt"] < job["retry_policy"]["max_attempts"]
        )
        if result["status"] is JobStatus.CANCELLED and stop.is_set():
            await self._release_if_owned(
                job["id"], fencing_token=fencing_token, refund_attempt=True
            )
            return None
        if retry_allowed and failure is not None:
            async with self._database.transaction() as repositories:
                await repositories.jobs.record_attempt_failure(
                    job["id"],
                    attempt=job["attempt"],
                    owner=self._settings.consumer_name,
                    fencing_token=fencing_token,
                    failure=failure,
                )
            return job["retry_policy"]["backoff_seconds"]

        async with self._database.transaction() as repositories:
            await repositories.jobs.complete(
                result,
                owner=self._settings.consumer_name,
                fencing_token=fencing_token,
            )
            if self._settlement_hook is not None:
                await self._settlement_hook.after_terminal(repositories, job, result)
        if result["status"] is JobStatus.FAILED and failure is not None:
            await self._queue.dead_letter(
                message.stream,
                self._settings.consumer_group,
                message,
                failure=failure,
                attempt=job["attempt"],
            )
        else:
            await self._acknowledge(message)
        return None

    async def _finalize_exhausted(
        self, message: StreamMessage, job: Job, *, fencing_token: str
    ) -> None:
        failure = StructuredFailure(
            code="worker.attempts_exhausted",
            kind=FailureKind.TOOL,
            message="job execution attempts were exhausted",
            retryable=False,
            details={"attempt": job["attempt"]},
        )
        result = _failed_result(job["id"], failure)
        async with self._database.transaction() as repositories:
            await repositories.jobs.fail_exhausted(
                result,
                owner=self._settings.consumer_name,
                fencing_token=fencing_token,
            )
            if self._settlement_hook is not None:
                await self._settlement_hook.after_terminal(repositories, job, result)
        await self._queue.dead_letter(
            message.stream,
            self._settings.consumer_group,
            message,
            failure=failure,
            attempt=job["attempt"],
        )

    async def _settle_existing_terminal(self, message: StreamMessage, job: Job) -> None:
        if job["status"] is JobStatus.WAITING_PERMISSION:
            return
        if (
            self._settlement_hook is not None
            and job["status"] in {JobStatus.SUCCEEDED, JobStatus.FAILED, JobStatus.CANCELLED}
        ):
            result = WorkerResult(
                schema_version=SchemaVersion.VALUE_1_0_0,
                job_id=job["id"],
                status=job["status"],
                produced_artifact_version_ids=[],
                evidence_ids=[],
                failure=job["failure"],
            )
            async with self._database.transaction() as repositories:
                await self._settlement_hook.after_terminal(repositories, job, result)
        if job["status"] is JobStatus.FAILED and job["failure"] is not None:
            await self._queue.dead_letter(
                message.stream,
                self._settings.consumer_group,
                message,
                failure=job["failure"],
                attempt=job["attempt"],
            )
            return
        if job["status"] in {JobStatus.SUCCEEDED, JobStatus.CANCELLED}:
            await self._acknowledge(message)

    async def _release_if_owned(
        self, job_id: str, *, fencing_token: str, refund_attempt: bool
    ) -> None:
        try:
            async with self._database.transaction() as repositories:
                await repositories.jobs.release_lease(
                    job_id,
                    owner=self._settings.consumer_name,
                    fencing_token=fencing_token,
                    refund_attempt=refund_attempt,
                )
        except JobLeaseConflict:
            LOGGER.warning("worker_lease_release_skipped", extra={"job_id": job_id})

    async def _recover_settlement(
        self,
        message: StreamMessage,
        error: JobLeaseConflict | PersistenceInvariantError,
    ) -> None:
        LOGGER.warning(
            "worker_result_settlement_conflict",
            extra={
                "job_id": message.event["aggregate_id"],
                "error_code": error.code,
            },
        )
        async with self._database.transaction() as repositories:
            current = await repositories.jobs.get(message.event["aggregate_id"])
        await self._settle_existing_terminal(message, current)

    @staticmethod
    async def _wait_for_retry(delay_seconds: float, stop: asyncio.Event) -> bool:
        if delay_seconds <= 0:
            return not stop.is_set()
        try:
            await asyncio.wait_for(stop.wait(), timeout=delay_seconds)
        except TimeoutError:
            return True
        return False

    async def _acknowledge(self, message: StreamMessage) -> None:
        await self._queue.acknowledge(
            message.stream, self._settings.consumer_group, message.message_id
        )


def _failed_result(job_id: str, failure: StructuredFailure) -> WorkerResult:
    return WorkerResult(
        schema_version=SchemaVersion.VALUE_1_0_0,
        job_id=job_id,
        status=JobStatus.FAILED,
        produced_artifact_version_ids=[],
        evidence_ids=[],
        failure=failure,
    )


def _unexpected_failure_result(job_id: str, error: Exception) -> WorkerResult:
    failure = StructuredFailure(
        code="worker.execution_error",
        kind=FailureKind.INTERNAL,
        message="worker executor raised an unexpected error",
        retryable=True,
        details={"exception_type": type(error).__name__},
    )
    return _failed_result(job_id, failure)


def _fencing_token(job: Job) -> str:
    lease = job["lease"]
    if lease is None or "fencing_token" not in lease:
        raise PersistenceInvariantError(
            "claimed job is missing its lease fencing token",
            details={"job_id": job["id"]},
        )
    return lease["fencing_token"]
