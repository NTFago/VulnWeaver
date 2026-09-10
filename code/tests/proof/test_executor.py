from __future__ import annotations

import asyncio
from typing import cast

from vulnweaver_contracts import (
    FindingStatus,
    Job,
    JobKind,
    JobStatus,
    PocKind,
    ProofRequest,
    ResourceBudget,
    SandboxResult,
    SandboxStatus,
)
from vulnweaver_persistence import Database
from vulnweaver_proof import ProofExecutionService, ProofJobExecutor

IMAGE_DIGEST = "sha256:" + "a" * 64


def _request() -> ProofRequest:
    return cast(
        ProofRequest,
        {
            "schema_version": "1.0.0",
            "id": "poc:proof-test",
            "job_id": "job:proof-test",
            "finding_id": "finding:proof-test",
            "script_ref": "cas://" + "b" * 64,
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


def _result(status: SandboxStatus) -> SandboxResult:
    return cast(
        SandboxResult,
        {
            "schema_version": "1.0.0",
            "request_id": "sandbox-request:poc:proof-test",
            "status": status,
            "exit_code": 0 if status is SandboxStatus.SUCCEEDED else None,
            "stdout_ref": "cas://stdout" if status is SandboxStatus.SUCCEEDED else None,
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


class _FakeSandbox:
    def __init__(self, result: SandboxResult) -> None:
        self.result = result
        self.requests: list[object] = []

    async def run(self, request: object, cancellation: asyncio.Event) -> SandboxResult:
        self.requests.append(request)
        return self.result


def _job(**kwargs: object) -> Job:
    return cast(
        Job,
        {
            "schema_version": "1.0.0",
            "id": "job:proof-test",
            "task_id": "task:proof-test",
            "kind": kwargs.get("kind", JobKind.PROOF),
            "input_refs": [],
            "status": JobStatus.QUEUED,
            "idempotency_key": "proof-test",
            "resource_budget": _request()["resource_budget"],
            "retry_policy": {
                "max_attempts": 1,
                "backoff_seconds": 1,
                "retryable_failure_kinds": [],
            },
            "attempt": 0,
            "lease": None,
            "failure": None,
            "created_at": "2026-01-01T00:00:00+00:00",
            "updated_at": "2026-01-01T00:00:00+00:00",
            **({"arguments": kwargs["arguments"]} if "arguments" in kwargs else {}),
        },
    )


def test_worker_adapter_rejects_non_proof_jobs_without_database_access() -> None:
    executor = ProofJobExecutor(cast(Database, None), cast(ProofExecutionService, None))
    result = asyncio.run(executor.execute(_job(kind=JobKind.REVIEW), asyncio.Event()))
    assert result["status"] == JobStatus.FAILED
    assert result["failure"]["code"] == "proof.invalid_job_kind"


def test_worker_adapter_rejects_missing_structured_request_without_database_access() -> None:
    executor = ProofJobExecutor(cast(Database, None), cast(ProofExecutionService, None))
    result = asyncio.run(executor.execute(_job(), asyncio.Event()))
    assert result["status"] == JobStatus.FAILED
    assert result["failure"]["code"] == "proof.request_required"


def test_exploit_is_policy_denied_before_sandbox_for_unconfirmed_finding() -> None:
    sandbox = _FakeSandbox(_result(SandboxStatus.SUCCEEDED))
    service = ProofExecutionService(sandbox, tool_name="proof", tool_version="1.0.0")

    poc = asyncio.run(
        service.run(
            _request(),
            finding_status=FindingStatus.CANDIDATE,
            exploit_validation_enabled=True,
            cancellation=asyncio.Event(),
            kind=PocKind.EXPLOIT,
        )
    )

    assert poc["result"] == "policy_denied"
    assert poc["status"] == "failed"
    assert sandbox.requests == []


def test_proof_binds_script_and_pinned_policy_to_sandbox() -> None:
    sandbox = _FakeSandbox(_result(SandboxStatus.SUCCEEDED))
    service = ProofExecutionService(sandbox, tool_name="proof", tool_version="1.0.0")

    poc = asyncio.run(
        service.run(
            _request(),
            finding_status=FindingStatus.CONFIRMED,
            exploit_validation_enabled=False,
            cancellation=asyncio.Event(),
        )
    )

    request = cast(dict[str, object], sandbox.requests[0])
    assert request["input_ref"] == _request()["script_ref"]
    assert request["image_digest"] == IMAGE_DIGEST
    assert request["tool_name"] == "proof"
    assert poc["result"] == "exploitable"
    assert poc["status"] == "completed"
    assert poc["run_log_ref"] == "cas://stdout"


def test_sandbox_budget_is_clamped_to_the_proof_tool_limits() -> None:
    """Proof requests carry the project budget; the Runner refuses anything above the spec."""

    limits = cast(
        ResourceBudget,
        {
            "max_model_tokens": 0,
            "cpu_millis": 1000,
            "memory_bytes": 256 * 1024 * 1024,
            "disk_bytes": 256 * 1024 * 1024,
            "max_tool_concurrency": 1,
            "max_dynamic_runs": 1,
            "timeout_seconds": 120,
        },
    )
    sandbox = _FakeSandbox(_result(SandboxStatus.SUCCEEDED))
    service = ProofExecutionService(
        sandbox, tool_name="proof", tool_version="1.0.0", resource_limits=limits
    )
    request = _request()
    request["resource_budget"] = cast(
        ResourceBudget,
        {
            **request["resource_budget"],
            "cpu_millis": 8000,
            "memory_bytes": 3 * 1024**3,
            "disk_bytes": 10 * 1024**3,
            "timeout_seconds": 3600,
        },
    )
    request["timeout_seconds"] = 3600

    asyncio.run(
        service.run(
            request,
            finding_status=FindingStatus.CONFIRMED,
            exploit_validation_enabled=False,
            cancellation=asyncio.Event(),
        )
    )

    sandbox_request = cast(dict[str, object], sandbox.requests[0])
    budget = cast(dict[str, int], sandbox_request["resource_budget"])
    assert budget["cpu_millis"] == limits["cpu_millis"]
    assert budget["memory_bytes"] == limits["memory_bytes"]
    assert budget["disk_bytes"] == limits["disk_bytes"]
    assert sandbox_request["timeout_seconds"] == limits["timeout_seconds"]


def test_sandbox_timeout_and_cancel_are_not_reported_as_exploitable() -> None:
    for status, expected in (
        (SandboxStatus.TIMED_OUT, "timeout"),
        (SandboxStatus.CANCELLED, "environment_error"),
    ):
        sandbox = _FakeSandbox(_result(status))
        service = ProofExecutionService(sandbox, tool_name="proof", tool_version="1.0.0")
        poc = asyncio.run(
            service.run(
                _request(),
                finding_status=FindingStatus.CONFIRMED,
                exploit_validation_enabled=True,
                cancellation=asyncio.Event(),
            )
        )
        assert poc["result"] == expected
        assert poc["status"] in {"failed", "cancelled"}
