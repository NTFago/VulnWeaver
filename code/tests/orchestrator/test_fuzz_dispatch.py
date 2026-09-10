"""Automatic fuzz dispatch and its bounded target resolution."""

from typing import cast

import pytest
from vulnweaver_contracts import validate_contract
from vulnweaver_orchestrator import FuzzJobScheduler, FuzzTarget
from vulnweaver_persistence import Repositories

_TASK = {
    "schema_version": "1.0.0",
    "id": "task:fuzz-dispatch",
    "project_id": "project:fuzz-dispatch",
    "artifact_version_ids": ["artifact-version:target"],
    "status": "reviewing",
    "result": None,
    "idempotency_key": "task:fuzz-dispatch",
    "resource_budget": {
        "max_model_tokens": 0,
        "cpu_millis": 4000,
        "memory_bytes": 1024 * 1024 * 1024,
        "disk_bytes": 512 * 1024 * 1024,
        "max_tool_concurrency": 1,
        "max_dynamic_runs": 1,
        "timeout_seconds": 300,
    },
    "created_at": "2026-01-01T00:00:00Z",
    "updated_at": "2026-01-01T00:00:00Z",
}

_TARGET = FuzzTarget(
    artifact_version_id="artifact-version:target",
    target_ref="cas://sha256/" + "e" * 64,
    seed_refs=("cas://sha256/" + "f" * 64,),
    image_digest="sha256:" + "a" * 64,
    max_executions=100,
    max_duration_seconds=30,
    max_crashes=5,
)


class _Jobs:
    def __init__(self) -> None:
        self.enqueued: list[tuple[dict, dict]] = []

    async def enqueue_with_outbox(self, job, event):
        self.enqueued.append((job, event))
        return type("Result", (), {"created": True})()


class _FakeRepositories:
    """Minimal transaction-scoped repository stand-in."""

    def __init__(self) -> None:
        self.jobs = _Jobs()
        self.tasks = _Tasks()
        self.findings = _Findings()


class _Tasks:
    async def get(self, _task_id, **_kwargs):
        return _TASK


class _Findings:
    async def get(self, finding_id):
        return {"id": finding_id, "task_id": _TASK["id"]}


class _Database:
    def __init__(self, repositories: _FakeRepositories) -> None:
        self._repositories = repositories

    def transaction(self):
        return _Transaction(self._repositories)


class _Transaction:
    def __init__(self, repositories) -> None:
        self._repositories = repositories

    async def __aenter__(self):
        return self._repositories

    async def __aexit__(self, *_exc) -> bool:
        return False


def _scheduler(resolver) -> tuple[FuzzJobScheduler, _FakeRepositories]:
    repositories = _FakeRepositories()
    scheduler = FuzzJobScheduler(
        cast(Repositories, _Database(repositories)), target_resolver=resolver
    )
    return scheduler, repositories


@pytest.mark.anyio
async def test_dispatch_enqueues_a_request_bound_to_the_new_job():
    async def resolver(_repositories, _finding, _task) -> FuzzTarget:
        return _TARGET

    scheduler, repositories = _scheduler(resolver)

    job_id = await scheduler.schedule_finding_in_transaction(
        cast(Repositories, repositories), "finding:1"
    )

    assert job_id is not None
    job, event = repositories.jobs.enqueued[0]
    assert job["id"] == job_id
    assert job["kind"] == "fuzz"
    request = job["arguments"]["fuzz_request"]
    # A request the executor will reject would only surface as a failed Job later.
    assert request["job_id"] == job["id"]
    validate_contract("FuzzRequest", request)
    assert event["payload"]["job_kind"] == "fuzz"


@pytest.mark.anyio
async def test_dispatch_declines_when_no_bounded_target_exists():
    async def resolver(_repositories, _finding, _task) -> None:
        return None

    scheduler, repositories = _scheduler(resolver)

    job_id = await scheduler.schedule_finding_in_transaction(
        cast(Repositories, repositories), "finding:1"
    )

    assert job_id is None
    assert repositories.jobs.enqueued == []


@pytest.mark.anyio
async def test_dispatch_is_disabled_without_a_resolver():
    scheduler, repositories = _scheduler(None)

    job_id = await scheduler.schedule_finding_in_transaction(
        cast(Repositories, repositories), "finding:1"
    )

    assert job_id is None
    assert repositories.jobs.enqueued == []
