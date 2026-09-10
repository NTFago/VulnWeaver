from __future__ import annotations

import asyncio
from typing import cast

import pytest
from vulnweaver_contracts import (
    Finding,
    FindingCategory,
    FindingStatus,
    JobKind,
    JobStatus,
    PocKind,
    ProofRequest,
    SandboxResult,
    SandboxStatus,
    Severity,
)
from vulnweaver_persistence import Database, DatabaseSettings, EntityNotFound
from vulnweaver_proof import ProofExecutionService, ProofJobExecutor, ProofJobScheduler

from tests.persistence.factories import artifact, artifact_version, project, task

OWNER_PROJECT = "project:proof-owner"
OTHER_PROJECT = "project:proof-other"
OWNED_VERSION = "artifact-version:proof-owned"
FOREIGN_VERSION = "artifact-version:proof-foreign"
FINDING_ID = "finding:proof-owner"
TASK_ID = "task:proof-owner"
IMAGE_DIGEST = "sha256:" + "a" * 64


def _object_ref(character: str) -> str:
    return "cas://sha256/" + character * 64


def _proof_request(*, script_ref: str, job_id: str = "job:proof-sched") -> ProofRequest:
    return cast(
        ProofRequest,
        {
            "schema_version": "1.0.0",
            "id": "poc:" + job_id,
            "job_id": job_id,
            "finding_id": FINDING_ID,
            "script_ref": script_ref,
            "image_digest": IMAGE_DIGEST,
            "permission_mode": "request_permission",
            "resource_budget": {
                "max_model_tokens": 0,
                "cpu_millis": 1000,
                "memory_bytes": 1048576,
                "disk_bytes": 1048576,
                "max_tool_concurrency": 1,
                "max_dynamic_runs": 1,
                "timeout_seconds": 30,
            },
            "timeout_seconds": 20,
        },
    )


async def _seed(database_url: str) -> None:
    database = Database(DatabaseSettings(database_url))
    async with database.transaction() as repositories:
        try:
            await repositories.findings.get(FINDING_ID)
            return
        except EntityNotFound:
            pass
        await repositories.projects.add(project(OWNER_PROJECT))
        await repositories.projects.add(project(OTHER_PROJECT))
        await repositories.artifacts.add(
            artifact(
                "artifact:proof-owned",
                project_id=OWNER_PROJECT,
                current_version_id=OWNED_VERSION,
            )
        )
        await repositories.artifacts.add_version(
            artifact_version(
                OWNED_VERSION, artifact_id="artifact:proof-owned", digest_character="b"
            )
        )
        await repositories.artifacts.add(
            artifact(
                "artifact:proof-foreign",
                project_id=OTHER_PROJECT,
                current_version_id=FOREIGN_VERSION,
            )
        )
        await repositories.artifacts.add_version(
            artifact_version(
                FOREIGN_VERSION,
                artifact_id="artifact:proof-foreign",
                digest_character="c",
            )
        )
        # The same digest is registered under both projects, which is why
        # script_ref ownership must be resolved per project scope.
        await repositories.artifacts.add_version(
            artifact_version(
                "artifact-version:proof-foreign-shared",
                artifact_id="artifact:proof-foreign",
                digest_character="b",
            )
        )
        await repositories.tasks.create(
            task(
                TASK_ID,
                project_id=OWNER_PROJECT,
                artifact_version_ids=[OWNED_VERSION],
                idempotency_key="task:proof-owner-key",
            )
        )
        finding = cast(
            Finding,
            {
                "schema_version": "1.0.0",
                "id": FINDING_ID,
                "task_id": TASK_ID,
                "category": FindingCategory.STATIC_ONLY,
                "cwe_id": "CWE-95",
                "title": "Unsafe eval",
                "severity": Severity.HIGH,
                "confidence": 0.7,
                "location": {
                    "artifact_version_id": OWNED_VERSION,
                    "path": "src/app.py",
                    "start_line": 2,
                    "start_column": 1,
                    "end_line": 2,
                    "end_column": 10,
                },
                "dataflow": [],
                "call_path": [],
                "status": FindingStatus.CONFIRMED,
                "evidence_ids": [],
                "review_ids": [],
                "poc_ids": [],
                "fix_suggestion": "Avoid eval on untrusted input",
                "created_at": "2026-09-09T08:00:00Z",
            },
        )
        await repositories.findings.create(finding)


@pytest.fixture
def proof_database_url(persistence_database_url: str) -> str:
    asyncio.run(_seed(persistence_database_url))
    return persistence_database_url


def _scheduler() -> ProofJobScheduler:
    return ProofJobScheduler(
        tool=cast(
            object,
            {"name": "proof-tool", "version": "1.0.0", "image_digest": IMAGE_DIGEST},
        )
    )


def test_scheduler_accepts_script_ref_owned_by_the_task_project(proof_database_url: str) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(proof_database_url))
        async with database.transaction() as repositories:
            scheduled = await _scheduler().schedule(
                repositories,
                _proof_request(script_ref=_object_ref("b")),
                kind=PocKind.PROOF_OF_CONCEPT,
            )
            assert scheduled["kind"] is JobKind.PROOF
            assert scheduled["task_id"] == TASK_ID

    asyncio.run(scenario())


def test_scheduler_rejects_script_ref_from_another_project(proof_database_url: str) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(proof_database_url))
        async with database.transaction() as repositories:
            with pytest.raises(PermissionError):
                await _scheduler().schedule(
                    repositories,
                    _proof_request(script_ref=_object_ref("c")),
                    kind=PocKind.PROOF_OF_CONCEPT,
                )

    asyncio.run(scenario())


def test_scheduler_rejects_unresolvable_script_ref(proof_database_url: str) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(proof_database_url))
        async with database.transaction() as repositories:
            with pytest.raises(PermissionError):
                await _scheduler().schedule(
                    repositories,
                    _proof_request(script_ref=_object_ref("d")),
                    kind=PocKind.PROOF_OF_CONCEPT,
                )

    asyncio.run(scenario())


class _RecordingSandbox:
    def __init__(self, result: SandboxResult) -> None:
        self.result = result
        self.calls: list[object] = []

    async def run(self, request: object, cancellation: asyncio.Event) -> SandboxResult:
        self.calls.append(request)
        return self.result


def _succeeded_result() -> SandboxResult:
    return cast(
        SandboxResult,
        {
            "schema_version": "1.0.0",
            "request_id": "sandbox-request:poc:job:proof-exec",
            "status": SandboxStatus.SUCCEEDED,
            "exit_code": 0,
            "stdout_ref": _object_ref("e"),
            "stderr_ref": None,
            "outputs": [],
            "resource_usage": {
                "duration_millis": 10,
                "cpu_millis": 5,
                "memory_bytes": 1024,
                "output_bytes": 0,
            },
            "failure": None,
        },
    )


def _executor_job(script_ref: str) -> dict[str, object]:
    request = dict(_proof_request(script_ref=script_ref, job_id="job:proof-exec"))
    return {
        "schema_version": "1.0.0",
        "id": "job:proof-exec",
        "task_id": TASK_ID,
        "kind": JobKind.PROOF,
        "input_refs": [script_ref],
        "status": JobStatus.QUEUED,
        "idempotency_key": "proof-exec",
        "resource_budget": request["resource_budget"],
        "retry_policy": {"max_attempts": 1, "backoff_seconds": 1, "retryable_failure_kinds": []},
        "attempt": 0,
        "lease": None,
        "failure": None,
        "created_at": "2026-09-09T08:00:00Z",
        "updated_at": "2026-09-09T08:00:00Z",
        "arguments": {"proof_request": request},
    }


def test_executor_runs_sandbox_outside_the_database_transaction_and_persists_the_poc(
    proof_database_url: str,
) -> None:
    sandbox = _RecordingSandbox(_succeeded_result())
    executor = ProofJobExecutor(
        Database(DatabaseSettings(proof_database_url)),
        ProofExecutionService(
            sandbox,
            tool_name="proof",
            tool_version="1.0.0",
        ),
    )

    result = asyncio.run(
        executor.execute(cast(object, _executor_job(_object_ref("b"))), asyncio.Event())
    )

    assert result["status"] is JobStatus.SUCCEEDED
    assert len(sandbox.calls) == 1
    async def verify() -> None:
        database = Database(DatabaseSettings(proof_database_url))
        async with database.transaction() as repositories:
            stored = await repositories.pocs.get("poc:job:proof-exec")
            assert stored["script_ref"] == _object_ref("b")

    asyncio.run(verify())


def test_executor_rejects_foreign_script_ref_without_invoking_the_sandbox(
    proof_database_url: str,
) -> None:
    sandbox = _RecordingSandbox(_succeeded_result())
    executor = ProofJobExecutor(
        Database(DatabaseSettings(proof_database_url)),
        ProofExecutionService(sandbox, tool_name="proof", tool_version="1.0.0"),
    )

    result = asyncio.run(
        executor.execute(cast(object, _executor_job(_object_ref("c"))), asyncio.Event())
    )

    assert result["status"] is JobStatus.FAILED
    assert result["failure"]["code"] == "proof.script_ref_outside_project"
    assert result["failure"]["kind"] == "policy"
    assert sandbox.calls == []


def test_executor_persists_failed_poc_when_the_sandbox_reports_failure(
    proof_database_url: str,
) -> None:
    failure_result = cast(
        SandboxResult,
        {
            "schema_version": "1.0.0",
            "request_id": "sandbox-request:poc:job:proof-exec",
            "status": SandboxStatus.POLICY_DENIED,
            "exit_code": None,
            "stdout_ref": None,
            "stderr_ref": None,
            "outputs": [],
            "resource_usage": {
                "duration_millis": 1,
                "cpu_millis": 0,
                "memory_bytes": 0,
                "output_bytes": 0,
            },
            "failure": None,
        },
    )
    executor = ProofJobExecutor(
        Database(DatabaseSettings(proof_database_url)),
        ProofExecutionService(
            _RecordingSandbox(failure_result),
            tool_name="proof",
            tool_version="1.0.0",
        ),
    )

    result = asyncio.run(
        executor.execute(cast(object, _executor_job(_object_ref("b"))), asyncio.Event())
    )

    assert result["status"] is JobStatus.FAILED
    assert result["failure"]["kind"] == "policy"
