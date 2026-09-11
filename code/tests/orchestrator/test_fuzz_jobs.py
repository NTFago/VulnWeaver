from typing import cast

import pytest
from vulnweaver_contracts import validate_contract
from vulnweaver_orchestrator.fuzz_jobs import (
    FuzzJobScheduler,
    FuzzTarget,
    link_fuzz_evidence,
    persist_crash_evidence,
)

_TASK = {
    "schema_version": "1.0.0",
    "id": "task:fuzz",
    "project_id": "project:fuzz",
    "artifact_version_ids": ["artifact-version:target"],
    "status": "analyzing",
    "pipeline": "binary_analysis",
    "input_refs": ["cas://sha256/" + "d" * 64],
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
_SOURCE_JOB = {
    "schema_version": "1.0.0",
    "id": "job:binary",
    "task_id": "task:fuzz",
    "kind": "binary_analysis",
    "input_refs": ["cas://sha256/" + "d" * 64],
    "status": "succeeded",
    "idempotency_key": "key",
    "resource_budget": _TASK["resource_budget"],
    "retry_policy": {"max_attempts": 1, "backoff_seconds": 0, "retryable_failure_kinds": []},
    "attempt": 0,
    "lease": None,
    "failure": None,
    "arguments": {},
    "created_at": "2026-01-01T00:00:00Z",
    "updated_at": "2026-01-01T00:00:00Z",
}


def _target() -> FuzzTarget:
    return FuzzTarget(
        artifact_version_id="artifact-version:target",
        target_ref="cas://sha256/" + "e" * 64,
        seed_refs=("cas://sha256/" + "f" * 64,),
        image_digest="sha256:" + "a" * 64,
        max_executions=100,
        max_duration_seconds=30,
        max_crashes=5,
    )


class _SchedulerRepositories:
    def __init__(self, finding_task_id: str = "task:fuzz") -> None:
        self.tasks = _Tasks(_TASK)
        self.findings = _FindingLookup(finding_task_id)
        self.jobs = _Jobs()


class _Tasks:
    def __init__(self, task: dict[str, object]) -> None:
        self._task = task

    async def get(self, _task_id, **_kwargs):
        return self._task


class _FindingLookup:
    def __init__(self, task_id: str) -> None:
        self._task_id = task_id

    async def get(self, finding_id: str):
        return {"id": finding_id, "task_id": self._task_id}


class _Jobs:
    def __init__(self) -> None:
        self.existing_ids: set[str] = set()
        self.enqueued: list[dict[str, object]] = []

    async def exists(self, job_id: str) -> bool:
        return job_id in self.existing_ids

    async def enqueue_with_outbox(self, job, event):
        self.enqueued.append({"job": job, "event": event})
        return type("Result", (), {"created": True})()


class _Transaction:
    def __init__(self, repositories) -> None:
        self._repositories = repositories

    async def __aenter__(self):
        return self._repositories

    async def __aexit__(self, *_exc) -> bool:
        return False


class _Database:
    def __init__(self, repositories) -> None:
        self._repositories = repositories

    def transaction(self):
        return _Transaction(self._repositories)


@pytest.mark.anyio
async def test_scheduler_binds_a_valid_fuzz_request_to_each_job():
    """The executor only accepts a request already bound to the Job it runs."""
    repositories = _SchedulerRepositories()
    scheduler = FuzzJobScheduler(cast("object", _Database(repositories)))  # type: ignore[arg-type]

    created = await scheduler.schedule(
        cast("object", _SOURCE_JOB), {"finding:1": _target()}  # type: ignore[arg-type]
    )

    assert len(created) == 1
    job = repositories.jobs.enqueued[0]["job"]
    assert job["id"] == created[0]
    assert job["kind"] == "fuzz"
    request = job["arguments"]["fuzz_request"]
    # The worker contract requires the request to name the Job that carries it.
    assert request["job_id"] == job["id"]
    validate_contract("FuzzRequest", request)
    assert request["seed_refs"] == list(_target().seed_refs)
    assert request["sandbox_request"]["image_digest"] == _target().image_digest
    assert repositories.jobs.enqueued[0]["event"]["payload"]["job_kind"] == "fuzz"


@pytest.mark.anyio
async def test_scheduler_rejects_a_finding_from_another_task():
    repositories = _SchedulerRepositories(finding_task_id="task:other")
    scheduler = FuzzJobScheduler(cast("object", _Database(repositories)))  # type: ignore[arg-type]

    with pytest.raises(ValueError):
        await scheduler.schedule(
            cast("object", _SOURCE_JOB), {"finding:1": _target()}  # type: ignore[arg-type]
        )

    assert repositories.jobs.enqueued == []


class Findings:
    def __init__(self):
        self.relations = []

    async def link_evidence(self, relation):
        self.relations.append(relation)
        return relation


class Repositories:
    def __init__(self):
        self.findings = Findings()
        self.evidence = Evidence()


class Evidence:
    def __init__(self):
        self.items = []

    async def create(self, evidence):
        self.items.append(evidence)
        return evidence


@pytest.mark.anyio
async def test_link_fuzz_evidence_is_deduplicated_and_supporting():
    repos = Repositories()
    linked = await link_fuzz_evidence(repos, finding_id="f", evidence_ids=["e2", "e1", "e2"],
                                      created_by="job", created_at="2026-01-01T00:00:00Z")
    assert linked == ("e1", "e2")
    assert [r["relation"] for r in repos.findings.relations] == ["supports", "supports"]


@pytest.mark.anyio
async def test_link_fuzz_evidence_rejects_invalid_weight():
    with pytest.raises(ValueError):
        await link_fuzz_evidence(Repositories(), finding_id="f", evidence_ids=[],
                                 created_by="job", created_at="now", weight=2)


@pytest.mark.anyio
async def test_persist_crash_evidence_stores_replayable_minimized_input():
    repos = Repositories()
    crash = {
        "schema_version": "1.0.0", "id": "crash", "artifact_version_id": "version",
        "input_ref": "cas://input", "input_digest": "sha256:" + "a" * 64,
        "signal": "SIGSEGV", "exit_code": 11, "stack_frames": [],
        "stack_hash": "sha256:" + "b" * 64, "stderr_ref": None,
        "fuzz_tool": {"name": "afl-casr", "version": "1", "image_digest": "sha256:" + "c" * 64},
        "tool": {"name": "casr", "version": "1", "image_digest": "sha256:" + "c" * 64},
        "created_at": "2026-01-01T00:00:00Z",
    }
    linked = await persist_crash_evidence(repos, finding_id="f", crashes=[crash], created_by="job")
    assert len(linked) == 1
    assert repos.evidence.items[0]["type"] == "crash_record"
    assert repos.evidence.items[0]["replay_recipe"]["reproducible"] is True
