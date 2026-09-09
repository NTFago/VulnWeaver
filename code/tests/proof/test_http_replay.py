"""Opt-in T20 HTTP replay acceptance against a live Sandbox Runner.

Required environment:
- SANDBOX_RUNNER_URL: base URL of the running isolated Runner service.
- VULNWEAVER_PROOF_OK_REF / VULNWEAVER_PROOF_BAD_REF: harmless script objects
  already stored in the Runner's CAS (success and intentional failure).
- VULNWEAVER_PROOF_IMAGE_DIGEST: digest-pinned proof tool image.
"""

from __future__ import annotations

import asyncio
import os
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
    Severity,
)
from vulnweaver_persistence import Database, DatabaseSettings, EntityNotFound
from vulnweaver_proof import (
    ProofExecutionService,
    ProofJobExecutor,
    ProofJobScheduler,
    SandboxRunnerClient,
)

from tests.persistence.factories import artifact, artifact_version, project, task

RUNNER_URL = os.environ.get("SANDBOX_RUNNER_URL", "").strip()
OK_REF = os.environ.get("VULNWEAVER_PROOF_OK_REF", "").strip()
BAD_REF = os.environ.get("VULNWEAVER_PROOF_BAD_REF", "").strip()
IMAGE_DIGEST = os.environ.get("VULNWEAVER_PROOF_IMAGE_DIGEST", "").strip()

ENABLED_PROJECT = "project:proof-http-enabled"
DISABLED_PROJECT = "project:proof-http-disabled"
TIMESTAMP = "2026-09-10T08:00:00Z"

pytestmark = pytest.mark.skipif(
    not (RUNNER_URL and OK_REF and BAD_REF and IMAGE_DIGEST),
    reason=(
        "SANDBOX_RUNNER_URL, VULNWEAVER_PROOF_*_REF and VULNWEAVER_PROOF_IMAGE_DIGEST are required"
    ),
)


def _object_ref_hex(object_ref: str) -> str:
    assert object_ref.startswith("cas://sha256/")
    return object_ref.removeprefix("cas://sha256/")


def _budget() -> dict[str, int]:
    return {
        "max_model_tokens": 0,
        "cpu_millis": 1000,
        "memory_bytes": 268435456,
        "disk_bytes": 268435456,
        "max_tool_concurrency": 1,
        "max_dynamic_runs": 1,
        "timeout_seconds": 60,
    }


def _proof_request(
    *,
    request_id: str,
    finding_id: str,
    script_ref: str,
    kind: PocKind,
) -> ProofRequest:
    job_id = f"job:{request_id}"
    return cast(
        ProofRequest,
        {
            "schema_version": "1.0.0",
            "id": f"poc:{request_id}",
            "job_id": job_id,
            "finding_id": finding_id,
            "script_ref": script_ref,
            "image_digest": IMAGE_DIGEST,
            "permission_mode": "request_permission",
            "resource_budget": _budget(),
            "timeout_seconds": 30,
        },
    )


async def _seed(database_url: str) -> None:
    database = Database(DatabaseSettings(database_url))
    async with database.transaction() as repositories:
        try:
            await repositories.projects.get(ENABLED_PROJECT)
            return
        except EntityNotFound:
            pass
        enabled = project(ENABLED_PROJECT)
        disabled = project(DISABLED_PROJECT)
        disabled["exploit_validation_enabled"] = False
        await repositories.projects.add(enabled)
        await repositories.projects.add(disabled)
        for artifact_id, project_id, refs in (
            (
                "artifact:proof-http-enabled",
                ENABLED_PROJECT,
                (OK_REF, BAD_REF),
            ),
            (
                "artifact:proof-http-disabled",
                DISABLED_PROJECT,
                (OK_REF,),
            ),
        ):
            version_ids: list[str] = []
            for index, _ref in enumerate(refs):
                version_ids.append(f"artifact-version:{artifact_id}:{index}")
            await repositories.artifacts.add(
                artifact(
                    artifact_id,
                    project_id=project_id,
                    current_version_id=version_ids[-1],
                )
            )
            for index, ref in enumerate(refs):
                version_id = f"artifact-version:{artifact_id}:{index}"
                await repositories.artifacts.add_version(
                    cast(
                        object,
                        {
                            **dict(artifact_version(version_id, artifact_id=artifact_id)),
                            "digest": "sha256:" + _object_ref_hex(ref),
                            "object_ref": ref,
                            "id": version_id,
                        },
                    )
                )
        for identifier, project_id, version_ids, finding_id, status in (
            (
                "task:proof-http-enabled",
                ENABLED_PROJECT,
                ["artifact-version:artifact:proof-http-enabled:0"],
                "finding:proof-http-enabled",
                FindingStatus.CONFIRMED,
            ),
            (
                "task:proof-http-disabled",
                DISABLED_PROJECT,
                ["artifact-version:artifact:proof-http-disabled:0"],
                "finding:proof-http-disabled",
                FindingStatus.CONFIRMED,
            ),
        ):
            await repositories.tasks.create(
                task(
                    identifier,
                    project_id=project_id,
                    artifact_version_ids=version_ids,
                    idempotency_key=identifier + "-key",
                )
            )
            await repositories.findings.create(
                cast(
                    Finding,
                    {
                        "schema_version": "1.0.0",
                        "id": finding_id,
                        "task_id": identifier,
                        "category": FindingCategory.STATIC_ONLY,
                        "cwe_id": "CWE-95",
                        "title": "Unsafe eval (http replay)",
                        "severity": Severity.HIGH,
                        "confidence": 0.7,
                        "location": {
                            "artifact_version_id": version_ids[0],
                            "path": "src/app.py",
                            "start_line": 2,
                            "start_column": 1,
                            "end_line": 2,
                            "end_column": 10,
                        },
                        "dataflow": [],
                        "status": status,
                        "evidence_ids": [],
                        "review_ids": [],
                        "poc_ids": [],
                        "fix_suggestion": "Avoid eval on untrusted input",
                        "created_at": TIMESTAMP,
                    },
                )
            )


@pytest.fixture
def proof_http_database_url(persistence_database_url: str) -> str:
    asyncio.run(_seed(persistence_database_url))
    return persistence_database_url


def _executor(database_url: str) -> ProofJobExecutor:
    return ProofJobExecutor(
        Database(DatabaseSettings(database_url)),
        ProofExecutionService(
            SandboxRunnerClient(RUNNER_URL, timeout_seconds=150.0),
            tool_name="proof-tool",
            tool_version="1.0.0",
        ),
    )


def _job_from(request: ProofRequest, kind: JobKind = JobKind.PROOF) -> dict[str, object]:
    return {
        "schema_version": "1.0.0",
        "id": request["job_id"],
        "task_id": request["finding_id"].replace("finding:", "task:"),
        "kind": kind,
        "input_refs": [request["script_ref"]],
        "status": JobStatus.QUEUED,
        "idempotency_key": request["id"],
        "resource_budget": request["resource_budget"],
        "retry_policy": {"max_attempts": 1, "backoff_seconds": 1, "retryable_failure_kinds": []},
        "attempt": 0,
        "lease": None,
        "failure": None,
        "created_at": TIMESTAMP,
        "updated_at": TIMESTAMP,
        "arguments": {"proof_request": dict(request)},
    }


def test_proof_request_with_cas_script_succeeds_over_http_runner(
    proof_http_database_url: str,
) -> None:
    request = _proof_request(
        request_id="proof-http-ok",
        finding_id="finding:proof-http-enabled",
        script_ref=OK_REF,
        kind=PocKind.PROOF_OF_CONCEPT,
    )
    result = asyncio.run(
        _executor(proof_http_database_url).execute(
            cast(object, _job_from(request)), asyncio.Event()
        )
    )

    assert result["status"] is JobStatus.SUCCEEDED, result["failure"]
    async def verify() -> None:
        database = Database(DatabaseSettings(proof_http_database_url))
        async with database.transaction() as repositories:
            poc = await repositories.pocs.get(request["id"])
            assert poc["status"] == "completed"
            assert poc["result"] == "exploitable"
            assert poc["run_log_ref"]

    asyncio.run(verify())


def test_proof_replay_is_idempotent_at_the_scheduler(proof_http_database_url: str) -> None:
    request = _proof_request(
        request_id="proof-http-replay",
        finding_id="finding:proof-http-enabled",
        script_ref=OK_REF,
        kind=PocKind.PROOF_OF_CONCEPT,
    )
    scheduler = ProofJobScheduler(
        tool=cast(object, {"name": "proof-tool", "version": "1.0.0", "image_digest": IMAGE_DIGEST})
    )

    async def scenario() -> tuple[str, str]:
        database = Database(DatabaseSettings(proof_http_database_url))
        async with database.transaction() as repositories:
            first = await scheduler.schedule(repositories, request, kind=PocKind.PROOF_OF_CONCEPT)
        async with database.transaction() as repositories:
            second = await scheduler.schedule(repositories, request, kind=PocKind.PROOF_OF_CONCEPT)
        return first["id"], second["id"]

    first_id, second_id = asyncio.run(scenario())
    assert first_id == second_id == request["job_id"]


def test_exploit_on_project_without_validation_is_policy_denied(
    proof_http_database_url: str,
) -> None:
    request = _proof_request(
        request_id="poc-exploit-http-denied",
        finding_id="finding:proof-http-disabled",
        script_ref=OK_REF,
        kind=PocKind.EXPLOIT,
    )
    result = asyncio.run(
        _executor(proof_http_database_url).execute(
            cast(object, _job_from(request, JobKind.EXPLOIT)), asyncio.Event()
        )
    )

    assert result["status"] is JobStatus.FAILED
    assert result["failure"]["kind"] == "policy"

    async def verify() -> None:
        database = Database(DatabaseSettings(proof_http_database_url))
        async with database.transaction() as repositories:
            poc = await repositories.pocs.get(request["id"])
            assert poc["result"] == "policy_denied"

    asyncio.run(verify())


def test_failing_script_is_a_structured_partial_failure(
    proof_http_database_url: str,
) -> None:
    request = _proof_request(
        request_id="proof-http-bad",
        finding_id="finding:proof-http-enabled",
        script_ref=BAD_REF,
        kind=PocKind.PROOF_OF_CONCEPT,
    )
    result = asyncio.run(
        _executor(proof_http_database_url).execute(
            cast(object, _job_from(request)), asyncio.Event()
        )
    )

    assert result["status"] is JobStatus.FAILED
    assert result["failure"]["kind"] == "tool"
    assert result["failure"]["code"] == "proof.tool_error"

    async def verify() -> None:
        database = Database(DatabaseSettings(proof_http_database_url))
        async with database.transaction() as repositories:
            poc = await repositories.pocs.get(request["id"])
            assert poc["status"] == "failed"
            assert poc["result"] == "tool_error"
            # The failed script wrote no stdout/stderr; the structured tool
            # result is the retained evidence for this partial failure.

    asyncio.run(verify())
