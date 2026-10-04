"""Worker-settlement regressions for paged fallback audit recovery (RP-01/RF-01/RF-02).

Both tests drive the real ``ReliableWorker`` settlement path — not a manual
second executor call — so the retryable bit, the job retry policy and the
checkpoint resume are exercised together:

* deadline stop: attempt 1 completes page 0, the paging deadline stops it
  before page 1, the worker re-queues, and attempt 2 resumes from the saved
  checkpoint and runs only the remaining page;
* gateway transport failure: attempt 1 completes page 0, the model transport
  fails on page 1 with a retryable DEPENDENCY failure, the worker re-queues,
  and attempt 2 resumes and finishes the remaining page.
"""

from __future__ import annotations

import asyncio
from typing import cast

from vulnweaver_contracts import (
    FailureKind,
    Job,
    JobStatus,
    RunStatus,
    StructuredFailure,
)
from vulnweaver_model_gateway import ModelCallResult
from vulnweaver_orchestrator import SemanticAuditJobExecutor, SemanticAuditor
from vulnweaver_orchestrator.checkpoints import InMemoryCheckpointStore
from vulnweaver_persistence import Database, DatabaseSettings
from vulnweaver_queue import QueueSettings, RedisStreamsClient
from vulnweaver_worker import ReliableWorker

from tests.orchestrator.test_semantic_audit import TIMESTAMP
from tests.orchestrator.test_semantic_audit_paging import (
    PageScriptedModel,
    seed_functions,
    semantic_job,
)
from tests.worker.test_worker import _wait_for_status, _worker_settings


class TripBeforeSecondPage:
    """Clock that trips exactly on the deadline check *after* page 0.

    Call map: call 1 initializes the attempt clock, call 2 is the deadline
    check before page 0 (passes, page 0 runs and is checkpointed), call 3 is
    the check before page 1 — that one reports an expired clock. Attempt 2
    then starts fresh (call 4) and its page-1 check (call 5) passes.
    """

    def __init__(self) -> None:
        self.calls = 0

    def __call__(self) -> float:
        self.calls += 1
        return 100.0 if self.calls == 3 else 0.0


class TransportFailsOnSecondPage:
    """Model that succeeds on page 0, fails page 1 once, then succeeds.

    The failure mirrors a real ``ModelTransportError`` as the gateway returns
    it through ``ModelCallResult.failure``: kind DEPENDENCY, retryable True.
    """

    def __init__(self) -> None:
        self.pages: list[list[str]] = []
        self._failed_once = False

    async def complete_structured(self, **kwargs: object) -> ModelCallResult:
        import json

        messages = cast(list[dict[str, str]], kwargs["messages"])
        payload = json.loads(messages[1]["content"])
        page_index = int(payload["page"]["index"])
        self.pages.append(
            [str(item["name"]) for item in payload["functions"] if isinstance(item, dict)]
        )
        run: dict[str, object] = {
            "schema_version": "1.0.0",
            "id": "agent-run:rf-negative",
            "task_id": "task:rf-negative",
            "status": RunStatus.SUCCEEDED,
            "model": "audit/test-model",
            "prompt_hash": "sha256:" + "a" * 64,
            "input_refs": [],
            "decisions": [],
            "token_usage": {"input_tokens": 10, "output_tokens": 10},
            "failure": None,
            "created_at": TIMESTAMP,
            "updated_at": TIMESTAMP,
        }
        if page_index == 1 and not self._failed_once:
            self._failed_once = True
            failure = StructuredFailure(
                code="model_transport_error",
                kind=FailureKind.DEPENDENCY,
                message="model request failed",
                retryable=True,
                details={},
            )
            failed_run = dict(run)
            failed_run["status"] = RunStatus.FAILED
            failed_run["failure"] = failure
            return ModelCallResult(None, failed_run, failure, "endpoint-1")  # type: ignore[arg-type]
        return ModelCallResult(
            {"schema_version": "1.0.0", "summary": "clean", "findings": []},
            run,  # type: ignore[arg-type]
            None,
            "endpoint-1",
        )


def test_deadline_after_page_zero_is_retried_and_resumes_remaining_page(
    persistence_database_url: str, redis_url: str, redis_namespace: str
) -> None:
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
            monotonic=TripBeforeSecondPage(),
        )
        stored = await _run_through_worker(
            database,
            redis_url,
            redis_namespace,
            "worker-semantic-deadline-retry",
            auditor,
            task_id,
            retryable_failure_kinds=[FailureKind.TIMEOUT],
        )
        assert stored["attempt"] == 2
        # Attempt 1 audited page 0 and checkpointed next_page=1; attempt 2
        # resumed and ran ONLY the remaining page — page 0 was never re-sent.
        assert model.pages == [names[:2], names[2:]]
        saved_states = [
            checkpoint.state for checkpoint in await checkpoints.list(task_id)
        ]
        assert any(state.get("next_page") == 1 for state in saved_states)
        final = saved_states[-1]
        assert final.get("completed") is True
        assert final.get("next_page") == 2
        await database.dispose()

    asyncio.run(scenario())


def test_transport_failure_on_second_page_is_retried_and_resumes(
    persistence_database_url: str, redis_url: str, redis_namespace: str
) -> None:
    """RF-01: the gateway's retryable verdict survives into the WorkerResult."""

    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        task_id, _version_id, names = await seed_functions(database, 4)
        model = TransportFailsOnSecondPage()
        checkpoints = InMemoryCheckpointStore()
        auditor = SemanticAuditor(
            database,
            model,
            store=_store(),
            fact_loader=_stub_loader(),
            checkpoint_store=checkpoints,
            fallback_page_size=2,
        )
        stored = await _run_through_worker(
            database,
            redis_url,
            redis_namespace,
            "worker-semantic-transport-retry",
            auditor,
            task_id,
            retryable_failure_kinds=[FailureKind.TIMEOUT, FailureKind.DEPENDENCY],
        )
        assert stored["attempt"] == 2
        assert stored["status"] is JobStatus.SUCCEEDED
        # Attempt 1: page 0 audited, page 1 failed with the transport error.
        # Attempt 2: resumed from the checkpoint and re-ran page 1 only —
        # page 0 was never re-sent to the model.
        assert model.pages == [names[:2], names[2:], names[2:]]
        saved_states = [
            checkpoint.state for checkpoint in await checkpoints.list(task_id)
        ]
        assert any(state.get("next_page") == 1 for state in saved_states)
        assert saved_states[-1].get("completed") is True
        await database.dispose()

    asyncio.run(scenario())


async def _run_through_worker(
    database: Database,
    redis_url: str,
    redis_namespace: str,
    consumer_name: str,
    auditor: SemanticAuditor,
    task_id: str,
    *,
    retryable_failure_kinds: list[FailureKind],
) -> Job:
    queue = RedisStreamsClient(QueueSettings(redis_url, namespace=redis_namespace))
    stop = asyncio.Event()
    worker = ReliableWorker(
        database,
        queue,
        SemanticAuditJobExecutor(database, auditor),
        _worker_settings(consumer_name),
    )
    suffix = task_id.removeprefix("task:")
    job_id = f"job:audit-retry:{suffix}"
    audit_job = semantic_job(job_id, task_id)
    try:
        await _enqueue_semantic(
            database, queue, audit_job, retryable_failure_kinds=retryable_failure_kinds
        )
        running = asyncio.create_task(worker.run(stop))
        stored = await _wait_for_status(database, job_id, JobStatus.SUCCEEDED, timeout=30)
        stop.set()
        await asyncio.wait_for(running, timeout=10)
        return stored
    finally:
        stop.set()
        # The worker settlement persists job results and attempt failures; the
        # session teardown downgrades migrations whose semantic-audit cleanup
        # cannot delete through those references, so remove our own rows first.
        await _delete_job_rows(database, job_id)


async def _enqueue_semantic(
    database: Database,
    queue: RedisStreamsClient,
    value: Job,
    *,
    retryable_failure_kinds: list[FailureKind],
) -> None:
    from tests.persistence.factories import job_event

    value["retry_policy"]["retryable_failure_kinds"] = retryable_failure_kinds
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
