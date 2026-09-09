from __future__ import annotations

import asyncio
from typing import cast

from vulnweaver_contracts import (
    FindingStatus,
    PocKind,
    ProofRequest,
    SandboxResult,
    SandboxStatus,
)
from vulnweaver_proof import ProofExecutionService

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
