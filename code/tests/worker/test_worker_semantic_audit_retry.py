"""RP-01: the paged fallback deadline stop is retried through worker settlement.

The executor returns a retryable TIMEOUT failure when the paging deadline
stops an attempt; the worker's settlement then records the attempt failure
and re-queues the job, and the next attempt resumes from the saved checkpoint
instead of leaving the remaining functions unaudited. This test drives the
real ``ReliableWorker`` settlement path — not a manual second executor call —
so the retryable bit, the job retry policy and the checkpoint resume are all
exercised together.
"""

from __future__ import annotations

import asyncio

from vulnweaver_contracts import FailureKind, Job, JobStatus
from vulnweaver_orchestrator import SemanticAuditJobExecutor, SemanticAuditor
from vulnweaver_orchestrator.checkpoints import InMemoryCheckpointStore
from vulnweaver_persistence import Database, DatabaseSettings
from vulnweaver_queue import QueueSettings, RedisStreamsClient
from vulnweaver_worker import ReliableWorker

from tests.orchestrator.test_semantic_audit_paging import (
    PageScriptedModel,
    seed_functions,
    semantic_job,
)
from tests.worker.test_worker import _wait_for_status, _worker_settings


def test_deadline_stop_is_retried_and_resumes_through_worker_settlement(
    persistence_database_url: str, redis_url: str, redis_namespace: str
) -> None:
    class TripOnceThenPass:
        """Deadline trips exactly on the first resume boundary (call 2)."""

        def __init__(self) -> None:
            self.calls = 0

        def __call__(self) -> float:
            self.calls += 1
            return 100.0 if self.calls == 2 else 0.0

    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        task_id, _version_id, names = await seed_functions(database, 4)
        model = PageScriptedModel([])
        checkpoints = InMemoryCheckpointStore()
        auditor = SemanticAuditor(
            database,
            model,
            store=_store(),
            fact_loader=_stub_loader(),
            checkpoint_store=checkpoints,
            fallback_page_size=2,
            fallback_deadline_seconds=50.0,
            monotonic=TripOnceThenPass(),
        )
        queue = RedisStreamsClient(QueueSettings(redis_url, namespace=redis_namespace))
        stop = asyncio.Event()
        worker = ReliableWorker(
            database,
            queue,
            SemanticAuditJobExecutor(database, auditor),
            _worker_settings("worker-semantic-deadline-retry"),
        )
        suffix = task_id.removeprefix("task:")
        job_id = f"job:audit-retry:{suffix}"
        audit_job = semantic_job(job_id, task_id)
        try:
            await _enqueue_semantic(database, queue, audit_job)
            running = asyncio.create_task(worker.run(stop))
            stored = await _wait_for_status(
                database, job_id, JobStatus.SUCCEEDED, timeout=30
            )
            stop.set()
            await asyncio.wait_for(running, timeout=10)
            assert stored["attempt"] == 2
            # Attempt 1 audited page 0, the resumed attempt page 1: together
            # every indexed function was audited across the two attempts.
            covered = [name for page in model.pages for name in page]
            assert sorted(covered) == sorted(names)
        finally:
            stop.set()
            # The worker settlement persists a job result; the session teardown
            # downgrades migrations whose semantic-audit cleanup cannot delete
            # through that reference, so the test removes its own rows first.
            await _delete_job_rows(database, job_id)
            await database.dispose()

    asyncio.run(scenario())


async def _enqueue_semantic(database: Database, queue: RedisStreamsClient, value: Job) -> None:
    from tests.persistence.factories import job_event

    value["retry_policy"]["retryable_failure_kinds"] = [FailureKind.TIMEOUT]
    value["retry_policy"]["backoff_seconds"] = 0
    value["retry_policy"]["max_attempts"] = 2
    event = job_event(value, f"event:{value['id']}")
    async with database.transaction() as repositories:
        await repositories.jobs.enqueue_with_outbox(value, event)
    await queue.publish(event)


async def _delete_job_rows(database: Database, job_id: str) -> None:
    from sqlalchemy import delete
    from vulnweaver_persistence.models import job_attempt_failures, job_results, jobs

    async with database.engine.begin() as connection:
        await connection.execute(
            delete(job_attempt_failures).where(job_attempt_failures.c.job_id == job_id)
        )
        await connection.execute(delete(job_results).where(job_results.c.job_id == job_id))
        await connection.execute(delete(jobs).where(jobs.c.id == job_id))


def _store():
    import tempfile

    from vulnweaver_artifact_store import LocalContentAddressedStore

    return LocalContentAddressedStore(tempfile.mkdtemp(prefix="vw-audit-retry-"))


def _stub_loader():
    from tests.orchestrator.test_semantic_audit import StubFactLoader

    return StubFactLoader()
