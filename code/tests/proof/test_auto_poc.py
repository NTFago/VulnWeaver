"""Candidate-stage PoC verification dispatch and execution tests."""

from __future__ import annotations

import asyncio
import io
import json
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

from vulnweaver_artifact_store import LocalContentAddressedStore
from vulnweaver_contracts import (
    ArtifactKind,
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

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures/proof"
CRAFTED_INPUT = "[" * 50000
CONTROL_INPUT = "[a]b=c\n"


class FakePocModel:
    def __init__(self, output: dict[str, object] | None = None) -> None:
        self._output = output or {
            "schema_version": "1.0.0",
            "driver": {"target_callable": "parse", "input_mode": "text"},
            "crafted_input": CRAFTED_INPUT,
            "control_input": CONTROL_INPUT,
            "rationale": "drive the original parser into unbounded recursion",
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
    """Completes the tool run without any trusted observation."""

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


class ObservationSandbox:
    """Completes the tool run with a trusted observation report in CAS."""

    def __init__(self, store: LocalContentAddressedStore, observation: dict[str, object]) -> None:
        payload = json.dumps(observation).encode("utf-8")
        stored = store.put_stream(io.BytesIO(payload), max_bytes=1024 * 1024)
        self._outputs = [
            {
                "path": "execution-report.json",
                "object_ref": stored.object_ref,
                "digest": stored.digest,
                "size_bytes": stored.size_bytes,
            }
        ]

    async def run(self, request: object, cancellation: object) -> SandboxResult:
        return cast(
            SandboxResult,
            {
                "schema_version": "1.0.0",
                "request_id": "sandbox-request:test",
                "status": SandboxStatus.SUCCEEDED,
                "exit_code": 0,
                "stdout_ref": None,
                "stderr_ref": None,
                "outputs": self._outputs,
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
    store: LocalContentAddressedStore | None = None,
    target_text: str | None = None,
) -> tuple[str, str]:
    project_id = f"project:{suffix}"
    version_id = f"artifact-version:{suffix}"
    task_id = f"task:{suffix}"
    value = _enabled_project(project_id) if enabled else dict(project(project_id))
    version = dict(artifact_version(version_id, artifact_id=f"artifact:{suffix}"))
    if store is not None and target_text is not None:
        stored = store.put_stream(
            io.BytesIO(target_text.encode("utf-8")), max_bytes=1024 * 1024
        )
        version["digest"] = stored.digest
        version["object_ref"] = stored.object_ref
    async with database.transaction() as repositories:
        await repositories.projects.add(cast(Any, value))
        await repositories.artifacts.add(
            artifact(
                f"artifact:{suffix}", project_id=project_id, current_version_id=version_id
            )
        )
        await repositories.artifacts.add_version(cast(Any, version))
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
                "category": FindingCategory.MEMORY_CORRUPTION,
                "cwe_id": "CWE-674",
                "title": "unbounded recursion in nested config parser",
                "severity": Severity.HIGH,
                "confidence": 0.7,
                "location": {
                    "artifact_version_id": version_id,
                    "path": "nested_config_parser.py",
                    "start_line": 20,
                    "start_column": 1,
                    "end_line": 20,
                    "end_column": 40,
                },
                "dataflow": [],
                "call_path": [],
                "status": status,
                "evidence_ids": [],
                "review_ids": [],
                "poc_ids": [],
                "fix_suggestion": "bound the recursion depth",
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


TARGET_SOURCE = FIXTURES / "nested_config_parser.py"


def test_poc_job_with_verified_trigger_creates_strong_target_bound_evidence(
    persistence_database_url: str, tmp_path: object
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        suffix = uuid4().hex
        store = LocalContentAddressedStore(cast(Any, tmp_path))
        target_text = TARGET_SOURCE.read_text(encoding="utf-8")
        task_id, finding_id = await _seed_finding(
            database, suffix, store=store, target_text=target_text
        )
        observation = {
            "schema_version": "1.0.0",
            "id": "observation:" + "a" * 32,
            "kind": "proof_of_concept",
            "finding_id": finding_id,
            "verdict": "verified_trigger",
            "verdict_reasons": [
                "target_crash_attributed", "control_input_clean", "replay_stable",
            ],
            "driver_digest": "sha256:" + "c" * 64,
            "target_binding": {
                "artifact_id": f"artifact:{suffix}",
                "version_id": f"artifact-version:{suffix}",
                "artifact_kind": "source_archive",
                "digest": "sha256:" + "d" * 64,
            },
            "inputs": [
                {"name": "inputs/0000", "digest": "sha256:" + "e" * 64, "size_bytes": 4}
            ],
            "controls": [
                {"name": "controls/0000", "digest": "sha256:" + "f" * 64, "size_bytes": 4}
            ],
            "runs": [
                {
                    "role": "control",
                    "input_name": "0000",
                    "exit_code": 0,
                    "signal": None,
                    "duration_millis": 3,
                    "target_frames": False,
                    "timed_out": False,
                }
            ],
            "trigger_runs": 3,
            "replay_runs": 2,
            "untrusted_claims": None,
            "verifier": {
                "name": "proof-entrypoint",
                "version": "2.0.0",
                "image_digest": None,
            },
            "created_at": TIMESTAMP,
        }
        executor = ProofJobExecutor(
            database,
            ProofExecutionService(
                ObservationSandbox(store, observation),
                tool_name="proof-tool",
                tool_version="1.0.0",
                store=store,
            ),
            store=store,
            script_generator=ExploitScriptGenerator(database, FakePocModel(), store),
        )
        try:
            proof_job = _poc_job(task_id, finding_id, suffix)
            result = await executor.execute(proof_job, asyncio.Event())
            assert result["status"] is JobStatus.SUCCEEDED, result["failure"]
            assert len(result["evidence_ids"]) == 1
            async with database.transaction() as repositories:
                pocs = await repositories.pocs.list_for_finding(finding_id)
                relations = await repositories.findings.list_evidence_relations(finding_id)
                evidence = await repositories.evidence.get(result["evidence_ids"][0])
                sample = await repositories.artifacts.get(f"artifact:{suffix}")
                bundle_version = await repositories.artifacts.find_project_version_by_object_ref(
                    pocs[0]["script_ref"], project_id=f"project:{suffix}"
                )
                assert bundle_version is not None
                bundle_artifact = await repositories.artifacts.get(bundle_version["artifact_id"])
            assert pocs[0]["result"] == "exploitable"
            assert pocs[0]["status"] == "completed"
            assert [item["evidence_id"] for item in relations] == result["evidence_ids"]
            assert evidence["type"] == "verification_observation"
            assert evidence["strength"] == "strong"
            assert evidence["replay_recipe"]["kind"] == "verification_observation"
            assert evidence["replay_recipe"]["reproducible"] is True
            # CR-03 invariant: the analyzed sample keeps its current version.
            assert sample["current_version_id"] == f"artifact-version:{suffix}"
            assert bundle_artifact["kind"] is ArtifactKind.DERIVED
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_poc_job_without_observation_stays_inconclusive_and_evidence_free(
    persistence_database_url: str, tmp_path: object
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        suffix = uuid4().hex
        store = LocalContentAddressedStore(cast(Any, tmp_path))
        task_id, finding_id = await _seed_finding(
            database, suffix, store=store,
            target_text=TARGET_SOURCE.read_text(encoding="utf-8"),
        )
        executor = ProofJobExecutor(
            database,
            ProofExecutionService(
                MarkerSandbox(None), tool_name="proof-tool", tool_version="1.0.0",
                store=store,
            ),
            store=store,
            script_generator=ExploitScriptGenerator(database, FakePocModel(), store),
        )
        try:
            result = await executor.execute(_poc_job(task_id, finding_id, suffix), asyncio.Event())
            assert result["status"] is JobStatus.SUCCEEDED, result["failure"]
            assert result["evidence_ids"] == []
            async with database.transaction() as repositories:
                pocs = await repositories.pocs.list_for_finding(finding_id)
                relations = await repositories.findings.list_evidence_relations(finding_id)
            assert pocs[0]["result"] == "inconclusive"
            assert relations == []
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_poc_job_rejected_observation_creates_no_evidence(
    persistence_database_url: str, tmp_path: object
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        suffix = uuid4().hex
        store = LocalContentAddressedStore(cast(Any, tmp_path))
        task_id, finding_id = await _seed_finding(
            database, suffix, store=store,
            target_text=TARGET_SOURCE.read_text(encoding="utf-8"),
        )
        observation = {
            "schema_version": "1.0.0",
            "id": "observation:" + "b" * 32,
            "kind": "proof_of_concept",
            "finding_id": finding_id,
            "verdict": "rejected_under_test_conditions",
            "verdict_reasons": ["no_trigger_observed"],
            "driver_digest": "sha256:" + "c" * 64,
            "target_binding": {
                "artifact_id": f"artifact:{suffix}",
                "version_id": f"artifact-version:{suffix}",
                "artifact_kind": "source_archive",
                "digest": "sha256:" + "d" * 64,
            },
            "inputs": [
                {"name": "inputs/0000", "digest": "sha256:" + "e" * 64, "size_bytes": 4}
            ],
            "controls": [
                {"name": "controls/0000", "digest": "sha256:" + "f" * 64, "size_bytes": 4}
            ],
            "runs": [],
            "trigger_runs": 0,
            "replay_runs": 0,
            "untrusted_claims": {
                "sink_reached": True, "source": "request", "sink": "eval",
            },
            "verifier": {
                "name": "proof-entrypoint",
                "version": "2.0.0",
                "image_digest": None,
            },
            "created_at": TIMESTAMP,
        }
        executor = ProofJobExecutor(
            database,
            ProofExecutionService(
                ObservationSandbox(store, observation),
                tool_name="proof-tool",
                tool_version="1.0.0",
                store=store,
            ),
            store=store,
            script_generator=ExploitScriptGenerator(database, FakePocModel(), store),
        )
        try:
            result = await executor.execute(_poc_job(task_id, finding_id, suffix), asyncio.Event())
            assert result["status"] is JobStatus.SUCCEEDED, result["failure"]
            assert result["evidence_ids"] == []
            async with database.transaction() as repositories:
                pocs = await repositories.pocs.list_for_finding(finding_id)
                relations = await repositories.findings.list_evidence_relations(finding_id)
            assert pocs[0]["result"] == "not_exploitable_under_environment"
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
        store = LocalContentAddressedStore(cast(Any, tmp_path))
        task_id, finding_id = await _seed_finding(
            database, suffix, status=FindingStatus.CONFIRMED, store=store,
            target_text=TARGET_SOURCE.read_text(encoding="utf-8"),
        )
        executor = ProofJobExecutor(
            database,
            ProofExecutionService(
                MarkerSandbox(None), tool_name="proof-tool", tool_version="1.0.0",
                store=store,
            ),
            store=store,
            script_generator=ExploitScriptGenerator(database, FakePocModel(), store),
        )
        try:
            result = await executor.execute(_poc_job(task_id, finding_id, suffix), asyncio.Event())
            assert result["status"] is JobStatus.FAILED
            assert result["failure"] is not None
            assert result["failure"]["code"] == "poc_verification.policy_denied"
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_poc_job_requires_crafted_and_control_inputs(
    persistence_database_url: str, tmp_path: object
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        suffix = uuid4().hex
        store = LocalContentAddressedStore(cast(Any, tmp_path))
        task_id, finding_id = await _seed_finding(
            database, suffix, store=store,
            target_text=TARGET_SOURCE.read_text(encoding="utf-8"),
        )
        model = FakePocModel({
            "schema_version": "1.0.0",
            "driver": {"target_callable": "parse", "input_mode": "text"},
            "rationale": "missing inputs",
        })
        executor = ProofJobExecutor(
            database,
            ProofExecutionService(
                MarkerSandbox(None), tool_name="proof-tool", tool_version="1.0.0",
                store=store,
            ),
            store=store,
            script_generator=ExploitScriptGenerator(database, model, store),
        )
        try:
            result = await executor.execute(_poc_job(task_id, finding_id, suffix), asyncio.Event())
            assert result["status"] is JobStatus.FAILED
            assert result["failure"]["code"] == "auto_exploit.crafted_input_required"
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
