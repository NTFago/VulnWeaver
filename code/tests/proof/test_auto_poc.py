"""Candidate-stage PoC verification dispatch and execution tests."""

from __future__ import annotations

import asyncio
import io
from typing import Any, cast
from uuid import uuid4

from vulnweaver_artifact_store import LocalContentAddressedStore
from vulnweaver_contracts import (
    Finding,
    FindingCategory,
    FindingStatus,
    Job,
    JobKind,
    JobStatus,
    RunStatus,
    SandboxResult,
    SandboxStatus,
    Severity,
)
from vulnweaver_model_gateway import ModelCallResult
from vulnweaver_orchestrator import TaskAggregateSettlementHook
from vulnweaver_persistence import Database, DatabaseSettings
from vulnweaver_proof import (
    ExploitScriptGenerator,
    PocVerificationScheduler,
    ProofExecutionService,
    ProofJobExecutor,
)

from tests.persistence.factories import artifact, artifact_version, job, project, task

IMAGE_DIGEST = "sha256:" + "a" * 64
TIMESTAMP = "2026-09-10T08:00:00Z"

POC_SCRIPT = (
    "value = eval('1 + 1')\n"
    'print("POC_MARKERS: {\\"sink_reached\\": true, '
    '\\"source\\": \\"request.query\\", \\"sink\\": \\"eval\\"}")\n'
)


class FakePocModel:
    def __init__(self, output: dict[str, object] | None = None) -> None:
        self._output = output or {
            "schema_version": "1.0.0",
            "script": POC_SCRIPT,
            "rationale": "minimal eval reproduction",
        }

    async def complete_structured(self, **kwargs: object) -> ModelCallResult:
        run = {
            "schema_version": "1.0.0",
            "id": "agent-run:stub",
            "task_id": "task:stub",
            "status": RunStatus.SUCCEEDED,
            "model": "planning/test",
            "prompt_hash": "sha256:" + "a" * 64,
            "input_refs": [],
            "decisions": [],
            "token_usage": {"input_tokens": 5, "output_tokens": 5},
            "failure": None,
            "created_at": TIMESTAMP,
            "updated_at": TIMESTAMP,
        }
        return ModelCallResult(self._output, run, None, "endpoint-1")  # type: ignore[arg-type]


class MarkerSandbox:
    """Succeeds and points stdout at a store object the test controls."""

    def __init__(self, stdout_ref: str | None) -> None:
        self._stdout_ref = stdout_ref

    async def run(self, request: object, cancellation: object) -> SandboxResult:
        return cast(
            SandboxResult,
            {
                "schema_version": "1.0.0",
                "request_id": "sandbox-request:test",
                "status": SandboxStatus.SUCCEEDED,
                "exit_code": 0,
                "stdout_ref": self._stdout_ref,
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


def _enabled_project(identifier: str) -> dict[str, object]:
    value = dict(project(identifier))
    value["exploit_validation_enabled"] = True
    return value


async def _seed_finding(
    database: Database,
    suffix: str,
    *,
    status: FindingStatus = FindingStatus.CANDIDATE,
    enabled: bool = True,
) -> tuple[str, str]:
    project_id = f"project:{suffix}"
    version_id = f"artifact-version:{suffix}"
    task_id = f"task:{suffix}"
    value = _enabled_project(project_id) if enabled else dict(project(project_id))
    async with database.transaction() as repositories:
        await repositories.projects.add(cast(Any, value))
        await repositories.artifacts.add(
            artifact(
                f"artifact:{suffix}", project_id=project_id, current_version_id=version_id
            )
        )
        await repositories.artifacts.add_version(
            artifact_version(version_id, artifact_id=f"artifact:{suffix}")
        )
        await repositories.tasks.create(
            task(
                task_id,
                project_id=project_id,
                artifact_version_ids=[version_id],
                idempotency_key=f"task-key:{suffix}",
            )
        )
        finding = cast(
            Finding,
            {
                "schema_version": "1.0.0",
                "id": f"finding:{suffix}",
                "task_id": task_id,
                "category": FindingCategory.INJECTION,
                "cwe_id": "CWE-95",
                "title": "eval on request data",
                "severity": Severity.HIGH,
                "confidence": 0.7,
                "location": {
                    "artifact_version_id": version_id,
                    "path": "src/app.py",
                    "start_line": 2,
                    "start_column": 1,
                    "end_line": 2,
                    "end_column": 24,
                },
                "dataflow": [],
                "call_path": [],
                "status": status,
                "evidence_ids": [],
                "review_ids": [],
                "poc_ids": [],
                "fix_suggestion": "avoid eval",
                "created_at": TIMESTAMP,
            },
        )
        await repositories.findings.create(finding)
    return task_id, f"finding:{suffix}"


def test_scheduler_dispatches_once_for_candidate_findings(persistence_database_url: str) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        suffix = uuid4().hex
        task_id, finding_id = await _seed_finding(database, suffix)
        scheduler = PocVerificationScheduler(database, image_digest=IMAGE_DIGEST)
        try:
            async with database.transaction() as repositories:
                first = await scheduler.schedule_in_transaction(repositories, finding_id)
                again = await scheduler.schedule_in_transaction(repositories, finding_id)
            assert first is not None
            assert again is None
            async with database.transaction() as repositories:
                jobs = await repositories.jobs.list_for_task(task_id)
            assert [item["kind"] for item in jobs] == [JobKind.PROOF]
            assert jobs[0]["arguments"]["poc_verification"]["image_digest"] == IMAGE_DIGEST
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_scheduler_skips_confirmed_findings_and_disabled_projects(
    persistence_database_url: str,
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        confirmed_suffix = uuid4().hex
        disabled_suffix = uuid4().hex
        _, confirmed_finding = await _seed_finding(
            database, confirmed_suffix, status=FindingStatus.CONFIRMED
        )
        _, disabled_finding = await _seed_finding(database, disabled_suffix, enabled=False)
        scheduler = PocVerificationScheduler(database, image_digest=IMAGE_DIGEST)
        try:
            async with database.transaction() as repositories:
                first = await scheduler.schedule_in_transaction(
                    repositories, confirmed_finding
                )
                second = await scheduler.schedule_in_transaction(
                    repositories, disabled_finding
                )
            assert first is None and second is None
        finally:
            await database.dispose()

    asyncio.run(scenario())


def _poc_job(task_id: str, finding_id: str, suffix: str) -> Job:
    proof_job = job(
        f"job:poc:{suffix}",
        task_id=task_id,
        idempotency_key=f"poc:{suffix}",
        kind=JobKind.PROOF,
    )
    proof_job["arguments"] = {
        "poc_verification": {"finding_id": finding_id, "image_digest": IMAGE_DIGEST}
    }
    return cast(Job, proof_job)


def test_poc_job_does_not_promote_self_reported_markers_to_evidence(
    persistence_database_url: str, tmp_path: object
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        suffix = uuid4().hex
        task_id, finding_id = await _seed_finding(database, suffix)
        store = LocalContentAddressedStore(cast(Any, tmp_path))
        stdout = store.put_stream(
            io.BytesIO(
                b"running repro\n"
                b'POC_MARKERS: {"sink_reached": true, "source": "request.query", '
                b'"sink": "eval(expr)"}\n'
            ),
            max_bytes=256 * 1024,
        )
        generator = ExploitScriptGenerator(database, FakePocModel(), store)
        executor = ProofJobExecutor(
            database,
            ProofExecutionService(
                MarkerSandbox(stdout.object_ref), tool_name="proof-tool", tool_version="1.0.0"
            ),
            script_generator=generator,
        )
        try:
            result = await executor.execute(_poc_job(task_id, finding_id, suffix), asyncio.Event())
            assert result["status"] is JobStatus.SUCCEEDED, result["failure"]
            assert result["evidence_ids"] == []
            async with database.transaction() as repositories:
                pocs = await repositories.pocs.list_for_finding(finding_id)
                relations = await repositories.findings.list_evidence_relations(finding_id)
            assert pocs[0]["kind"] == "proof_of_concept"
            assert pocs[0]["result"] == "inconclusive"
            assert relations == []
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_poc_job_without_marker_line_produces_no_evidence(
    persistence_database_url: str, tmp_path: object
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        suffix = uuid4().hex
        task_id, finding_id = await _seed_finding(database, suffix)
        store = LocalContentAddressedStore(cast(Any, tmp_path))
        stdout = store.put_stream(io.BytesIO(b"nothing structured\n"), max_bytes=256 * 1024)
        generator = ExploitScriptGenerator(database, FakePocModel(), store)
        executor = ProofJobExecutor(
            database,
            ProofExecutionService(
                MarkerSandbox(stdout.object_ref), tool_name="proof-tool", tool_version="1.0.0"
            ),
            script_generator=generator,
        )
        try:
            result = await executor.execute(_poc_job(task_id, finding_id, suffix), asyncio.Event())
            assert result["status"] is JobStatus.SUCCEEDED, result["failure"]
            assert result["evidence_ids"] == []
            async with database.transaction() as repositories:
                relations = await repositories.findings.list_evidence_relations(finding_id)
            assert relations == []
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_poc_job_policy_denies_confirmed_finding(
    persistence_database_url: str, tmp_path: object
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        suffix = uuid4().hex
        task_id, finding_id = await _seed_finding(
            database, suffix, status=FindingStatus.CONFIRMED
        )
        store = LocalContentAddressedStore(cast(Any, tmp_path))
        generator = ExploitScriptGenerator(database, FakePocModel(), store)
        executor = ProofJobExecutor(
            database,
            ProofExecutionService(
                MarkerSandbox(None), tool_name="proof-tool", tool_version="1.0.0"
            ),
            script_generator=generator,
        )
        try:
            result = await executor.execute(_poc_job(task_id, finding_id, suffix), asyncio.Event())
            assert result["status"] is JobStatus.FAILED
            assert result["failure"] is not None
            assert result["failure"]["code"] == "poc_verification.policy_denied"
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_hook_dispatches_poc_after_audit_settlement(persistence_database_url: str) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        suffix = uuid4().hex
        task_id, _ = await _seed_finding(database, suffix)
        audit_job = job(
            f"job:audit:{suffix}",
            task_id=task_id,
            idempotency_key=f"audit:{suffix}",
            kind=JobKind.SEMANTIC_AUDIT,
        )
        audit_job["status"] = JobStatus.SUCCEEDED
        async with database.transaction() as repositories:
            await repositories.jobs.create_without_outbox(audit_job)
        scheduler = PocVerificationScheduler(database, image_digest=IMAGE_DIGEST)
        hook = TaskAggregateSettlementHook(None, None, None, scheduler)
        try:
            async with database.transaction() as repositories:
                await hook.after_terminal(
                    repositories,
                    audit_job,
                    {
                        "schema_version": "1.0.0",
                        "job_id": audit_job["id"],
                        "status": "succeeded",
                        "produced_artifact_version_ids": [],
                        "evidence_ids": [],
                        "failure": None,
                    },
                )
                jobs = await repositories.jobs.list_for_task(task_id)
            assert sorted(item["kind"] for item in jobs) == [
                JobKind.PROOF,
                JobKind.SEMANTIC_AUDIT,
            ]
        finally:
            await database.dispose()

    asyncio.run(scenario())
