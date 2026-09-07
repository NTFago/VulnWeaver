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
)
from vulnweaver_queue import RedisStreamsClient, StreamMessage

LOGGER = logging.getLogger("vulnweaver.worker")


class JobExecutor(Protocol):
    async def execute(self, job: Job, cancellation: asyncio.Event) -> WorkerResult: ...


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
    ) -> None:
        self._database = database
        self._queue = queue
        self._executor = executor
        self._settings = settings

    async def run(self, stop: asyncio.Event) -> None:
        """Consume until stopped, then drain or safely release in-flight leases."""

        stream = self._queue.streams.jobs
        await self._queue.ensure_group(stream, self._settings.consumer_group)
        running: set[asyncio.Task[None]] = set()
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

            claimed = await self._queue.claim_stale(
                stream,
                self._settings.consumer_group,
                self._settings.consumer_name,
                min_idle_milliseconds=self._settings.pending_idle_milliseconds,
                count=capacity,
            )
            messages = list(claimed.messages)
            if not messages:
                messages = await self._queue.read_group(
                    stream,
                    self._settings.consumer_group,
                    self._settings.consumer_name,
                    count=capacity,
                    block_milliseconds=self._settings.read_block_milliseconds,
                )
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
            async with self._database.transaction() as repositories:
                claim = await repositories.jobs.claim_lease(
                    message.event["aggregate_id"],
                    owner=self._settings.consumer_name,
                    lease_seconds=self._settings.lease_seconds,
                    heartbeat_interval_seconds=self._settings.heartbeat_interval_seconds,
                )
            if claim.outcome is JobLeaseClaimOutcome.BUSY:
                return
            if claim.outcome is JobLeaseClaimOutcome.COMPLETED:
                await self._acknowledge(message)
                return
            if claim.outcome is JobLeaseClaimOutcome.EXHAUSTED:
                await self._finalize_exhausted(message, claim.job)
                return
            if claim.outcome is JobLeaseClaimOutcome.NOT_RUNNABLE:
                await self._settle_existing_terminal(message, claim.job)
                return

            try:
                result = await self._execute_with_heartbeat(claim.job, stop)
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
                    claim.job["id"], ValueError("executor returned a different job identifier")
                )
            await self._settle_execution_result(message, claim.job, result, stop)
        except asyncio.CancelledError:
            if claim is not None and claim.outcome is JobLeaseClaimOutcome.ACQUIRED:
                await asyncio.shield(self._release_if_owned(claim.job["id"]))
            raise
        except Exception:
            LOGGER.exception(
                "worker_message_processing_failed",
                extra={"event_id": message.event["event_id"]},
            )

    async def _execute_with_heartbeat(self, job: Job, stop: asyncio.Event) -> WorkerResult:
        execution = asyncio.create_task(self._executor.execute(job, stop))
        heartbeat = asyncio.create_task(self._heartbeat(job["id"]))
        try:
            done, _ = await asyncio.wait(
                {execution, heartbeat}, return_when=asyncio.FIRST_COMPLETED
            )
            if heartbeat in done:
                execution.cancel()
                await asyncio.gather(execution, return_exceptions=True)
                try:
                    await heartbeat
                except Exception as error:
                    raise _LeaseHeartbeatFailed from error
                raise _LeaseHeartbeatFailed

            heartbeat.cancel()
            await asyncio.gather(heartbeat, return_exceptions=True)
            return await execution
        finally:
            for task in (execution, heartbeat):
                if not task.done():
                    task.cancel()
            await asyncio.gather(execution, heartbeat, return_exceptions=True)

    async def _heartbeat(self, job_id: str) -> None:
        while True:
            await asyncio.sleep(self._settings.heartbeat_interval_seconds)
            async with self._database.transaction() as repositories:
                await repositories.jobs.renew_lease(
                    job_id,
                    owner=self._settings.consumer_name,
                    lease_seconds=self._settings.lease_seconds,
                )

    async def _settle_execution_result(
        self,
        message: StreamMessage,
        job: Job,
        result: WorkerResult,
        stop: asyncio.Event,
    ) -> None:
        failure = result["failure"]
        if (result["status"] is JobStatus.CANCELLED and stop.is_set()) or (
            result["status"] is JobStatus.FAILED
            and failure is not None
            and failure["retryable"]
            and job["attempt"] < job["retry_policy"]["max_attempts"]
        ):
            await self._release_if_owned(job["id"])
            return

        async with self._database.transaction() as repositories:
            await repositories.jobs.complete(result, owner=self._settings.consumer_name)
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

    async def _finalize_exhausted(self, message: StreamMessage, job: Job) -> None:
        failure = StructuredFailure(
            code="worker.attempts_exhausted",
            kind=FailureKind.TOOL,
            message="job execution attempts were exhausted",
            retryable=False,
            details={"attempt": job["attempt"]},
        )
        result = _failed_result(job["id"], failure)
        async with self._database.transaction() as repositories:
            await repositories.jobs.fail_exhausted(result)
        await self._queue.dead_letter(
            message.stream,
            self._settings.consumer_group,
            message,
            failure=failure,
            attempt=job["attempt"],
        )

    async def _settle_existing_terminal(self, message: StreamMessage, job: Job) -> None:
        if job["status"] is JobStatus.FAILED and job["failure"] is not None:
            await self._queue.dead_letter(
                message.stream,
                self._settings.consumer_group,
                message,
                failure=job["failure"],
                attempt=job["attempt"],
            )
            return
        await self._acknowledge(message)

    async def _release_if_owned(self, job_id: str) -> None:
        try:
            async with self._database.transaction() as repositories:
                await repositories.jobs.release_lease(job_id, owner=self._settings.consumer_name)
        except JobLeaseConflict:
            LOGGER.warning("worker_lease_release_skipped", extra={"job_id": job_id})

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
