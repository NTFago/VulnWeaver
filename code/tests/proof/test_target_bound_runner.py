"""Opt-in ADR-036 P0 acceptance against a live Sandbox Runner and proof image.

Required environment:
- SANDBOX_RUNNER_URL: base URL of the running isolated Runner service.
- VULNWEAVER_SHARED_CAS_ROOT (default /var/lib/vulnweaver/artifacts): path
  where this process can write into the Runner's CAS volume.

The proof image must already be rebuilt with the target-bound entrypoint and
the Runner restarted so it re-resolved the image digest. Every case goes
through the full chain: driver generation → ExecutionBundle build → real
sandbox container → trusted observation → PoC/evidence persistence.
"""

from __future__ import annotations

import asyncio
import io
import os
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

import pytest
from vulnweaver_artifact_store import LocalContentAddressedStore
from vulnweaver_contracts import (
    Finding,
    FindingCategory,
    FindingStatus,
    Job,
    JobKind,
    JobStatus,
    RunStatus,
)
from vulnweaver_model_gateway import ModelCallResult
from vulnweaver_persistence import Database, DatabaseSettings
from vulnweaver_proof import (
    ExploitScriptGenerator,
    ProofExecutionService,
    ProofJobExecutor,
    SandboxRunnerClient,
)

from tests.persistence.factories import artifact, artifact_version, job, project, task

RUNNER_URL = os.environ.get("SANDBOX_RUNNER_URL", "").strip()
RUNNER_TOKEN = os.environ.get("SANDBOX_RUNNER_TOKEN", "").strip()
CAS_ROOT = os.environ.get("VULNWEAVER_SHARED_CAS_ROOT", "/var/lib/vulnweaver/artifacts").strip()


def _client(timeout_seconds: float) -> SandboxRunnerClient:
    return SandboxRunnerClient(
        RUNNER_URL,
        timeout_seconds=timeout_seconds,
        bearer_token=RUNNER_TOKEN or None,
    )

pytestmark = pytest.mark.skipif(
    not RUNNER_URL or not Path(CAS_ROOT).is_dir(),
    reason="SANDBOX_RUNNER_URL and a shared VULNWEAVER_SHARED_CAS_ROOT are required",
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures/proof"
TARGET_PATH = FIXTURES / "nested_config_parser.py"
CRAFTED = "[" * 50000
CONTROL = "[a]b=c\n"
TIMESTAMP = "2026-10-03T08:00:00Z"


class StubModel:
    """Returns one fixed invocation plus its crafted and control inputs."""

    def __init__(self, driver_name: str) -> None:
        self._output = {
            "schema_version": "1.0.0",
            "driver": {
                "target_callable": (
                    "parse" if driver_name == "driver_invoking_target.py"
                    else "missing_target_callable"
                ),
                "input_mode": "text",
            },
            "crafted_input": CRAFTED,
            "control_input": CONTROL,
            "rationale": "target-bound acceptance driver",
        }

    async def complete_structured(self, **kwargs: object) -> ModelCallResult:
        run = {
            "schema_version": "1.0.0",
            "id": "agent-run:acceptance",
            "task_id": "task:acceptance",
            "status": RunStatus.SUCCEEDED,
            "model": "planning/acceptance",
            "prompt_hash": "sha256:" + "a" * 64,
            "input_refs": [],
            "decisions": [],
            "token_usage": {"input_tokens": 5, "output_tokens": 5},
            "failure": None,
            "created_at": TIMESTAMP,
            "updated_at": TIMESTAMP,
        }
        return ModelCallResult(self._output, run, None, "endpoint-1")  # type: ignore[arg-type]


async def _seed(
    database: Database, store: LocalContentAddressedStore
) -> tuple[str, str, str]:
    suffix = uuid4().hex
    project_id = f"project:acceptance-{suffix}"
    artifact_id = f"artifact:acceptance-{suffix}"
    version_id = f"artifact-version:acceptance-{suffix}"
    task_id = f"task:acceptance-{suffix}"
    stored = store.put_stream(
        io.BytesIO(TARGET_PATH.read_bytes()), max_bytes=1024 * 1024
    )
    async with database.transaction() as repositories:
        seeded = dict(project(project_id))
        seeded["exploit_validation_enabled"] = True
        await repositories.projects.add(cast(Any, seeded))
        await repositories.artifacts.add(
            artifact(artifact_id, project_id=project_id, current_version_id=version_id)
        )
        version = dict(artifact_version(version_id, artifact_id=artifact_id))
        version["digest"] = stored.digest
        version["object_ref"] = stored.object_ref
        await repositories.artifacts.add_version(cast(Any, version))
        await repositories.tasks.create(
            task(
                task_id,
                project_id=project_id,
                artifact_version_ids=[version_id],
                idempotency_key=f"task-key:{suffix}",
            )
        )
        await repositories.findings.create(
            cast(
                Finding,
                {
                    "schema_version": "1.0.0",
                    "id": f"finding:acceptance-{suffix}",
                    "task_id": task_id,
                    "category": FindingCategory.MEMORY_CORRUPTION,
                    "cwe_id": "CWE-674",
                    "title": "unbounded recursion in nested config parser",
                    "severity": "high",
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
                    "status": FindingStatus.CANDIDATE,
                    "evidence_ids": [],
                    "review_ids": [],
                    "poc_ids": [],
                    "fix_suggestion": "bound the recursion depth",
                    "created_at": TIMESTAMP,
                },
            )
        )
    return task_id, f"finding:acceptance-{suffix}", artifact_id


def _run_case(
    database_url: str,
    store: LocalContentAddressedStore,
    task_id: str,
    finding_id: str,
    driver_name: str,
) -> Any:
    database = Database(DatabaseSettings(database_url))
    service = ProofExecutionService(
        _client(150.0),
        tool_name="proof-tool",
        tool_version="1.0.0",
        store=store,
    )
    executor = ProofJobExecutor(
        database,
        service,
        store=store,
        script_generator=ExploitScriptGenerator(database, StubModel(driver_name), store),
    )
    suffix = uuid4().hex
    proof_job = job(
        f"job:acceptance-poc:{suffix}",
        task_id=task_id,
        idempotency_key=f"acceptance-poc:{suffix}",
        kind=JobKind.PROOF,
    )
    proof_job["arguments"] = {
        "poc_verification": {
            "finding_id": finding_id,
            "image_digest": service_digest(store),
        }
    }
    return asyncio.run(executor.execute(cast(Job, proof_job), asyncio.Event()))


_DIGEST_CACHE: dict[str, str] = {}


def service_digest(store: LocalContentAddressedStore) -> str:
    if "digest" not in _DIGEST_CACHE:

        async def fetch() -> str:
            client = _client(30.0)
            digest = await client.tool_digest("proof-tool", "1.0.0")
            if digest is None:
                raise RuntimeError("proof-tool is not registered on the runner")
            return digest

        _DIGEST_CACHE["digest"] = asyncio.run(fetch())
    return _DIGEST_CACHE["digest"]


def test_real_runner_verifies_original_target_positive_case(
    persistence_database_url: str,
) -> None:
    store = LocalContentAddressedStore(CAS_ROOT)

    async def scenario() -> tuple[str, str, str]:
        database = Database(DatabaseSettings(persistence_database_url))
        seeded = await _seed(database, store)
        await database.dispose()
        return seeded

    task_id, finding_id, artifact_id = asyncio.run(scenario())
    result = _run_case(
        persistence_database_url, store, task_id, finding_id, "driver_invoking_target.py"
    )

    assert result["status"] is JobStatus.SUCCEEDED, result["failure"]
    assert len(result["evidence_ids"]) == 1

    async def verify() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        async with database.transaction() as repositories:
            pocs = await repositories.pocs.list_for_finding(finding_id)
            evidence = await repositories.evidence.get(result["evidence_ids"][0])
            relations = await repositories.findings.list_evidence_relations(finding_id)
            sample = await repositories.artifacts.get(artifact_id)
        assert pocs[0]["result"] == "exploitable"
        assert pocs[0]["status"] == "completed"
        assert evidence["type"] == "verification_observation"
        observation = evidence["replay_recipe"]["observation"]
        assert observation["verdict"] == "verified_trigger"
        assert observation["trigger_runs"] == 3
        assert observation["replay_runs"] == 2
        assert observation["inputs"][0]["size_bytes"] == len(CRAFTED.encode("utf-8"))
        assert [item["evidence_id"] for item in relations] == result["evidence_ids"]
        # The analyzed sample keeps its current version after the run.
        assert sample["current_version_id"].startswith("artifact-version:acceptance-")
        await database.dispose()

    asyncio.run(verify())


def test_real_runner_rejects_empty_and_forged_and_wrong_target_drivers(
    persistence_database_url: str,
) -> None:
    store = LocalContentAddressedStore(CAS_ROOT)

    async def seed() -> list[tuple[str, str, str]]:
        outcomes = []
        for driver_name in (
            "driver_noop.py",
            "driver_forged_markers.py",
            "driver_reimplemented.py",
        ):
            database = Database(DatabaseSettings(persistence_database_url))
            task_id, finding_id, _ = await _seed(database, store)
            await database.dispose()
            outcomes.append((driver_name, task_id, finding_id))
        return outcomes

    for driver_name, task_id, finding_id in asyncio.run(seed()):
        result = _run_case(
            persistence_database_url, store, task_id, finding_id, driver_name
        )
        assert result["status"] is JobStatus.SUCCEEDED, (driver_name, result["failure"])
        assert result["evidence_ids"] == [], driver_name

        async def verify(driver: str, finding: str) -> None:
            database = Database(DatabaseSettings(persistence_database_url))
            async with database.transaction() as repositories:
                pocs = await repositories.pocs.list_for_finding(finding)
                relations = await repositories.findings.list_evidence_relations(finding)
            assert pocs[0]["result"] == "not_exploitable_under_environment", driver
            assert relations == [], driver
            await database.dispose()

        asyncio.run(verify(driver_name, finding_id))
