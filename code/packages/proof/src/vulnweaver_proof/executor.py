"""Build and execute proof requests without giving callers command access."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Protocol, cast

from vulnweaver_contracts import (
    SCHEMA_VERSION,
    ArtifactKind,
    FindingStatus,
    Poc,
    PocKind,
    PocResult,
    PocStatus,
    ProofRequest,
    SandboxRequest,
    SandboxResult,
    SandboxStatus,
    validate_contract,
)
from vulnweaver_domain import evaluate_exploit_eligibility


class ProofSandbox(Protocol):
    async def run(self, request: SandboxRequest, cancellation: asyncio.Event) -> SandboxResult: ...


class ProofExecutionError(ValueError):
    """Raised when a proof request is malformed or its tool binding is unsafe."""


class ProofExecutionService:
    """Run one fixed proof/exploit tool through the Sandbox Runner."""

    def __init__(
        self,
        sandbox: ProofSandbox,
        *,
        tool_name: str,
        tool_version: str,
        output_file_names: tuple[str, ...] = ("proof-result.json",),
    ) -> None:
        if not tool_name or not tool_version or not output_file_names:
            raise ValueError("proof tool identity and outputs are required")
        self._sandbox = sandbox
        self._tool_name = tool_name
        self._tool_version = tool_version
        self._output_file_names = output_file_names

    async def run(
        self,
        request: ProofRequest,
        *,
        finding_status: FindingStatus,
        exploit_validation_enabled: bool,
        cancellation: asyncio.Event,
        kind: PocKind = PocKind.PROOF_OF_CONCEPT,
    ) -> Poc:
        try:
            validate_contract("ProofRequest", request)
        except (TypeError, ValueError) as error:
            raise ProofExecutionError("proof request does not satisfy its contract") from error

        decision = evaluate_exploit_eligibility(
            finding_status,
            exploit_validation_enabled=exploit_validation_enabled,
        )
        if kind is PocKind.EXPLOIT and not decision.allowed:
            return self._poc(request, kind, PocStatus.FAILED, PocResult.POLICY_DENIED)

        sandbox_request = cast(
            SandboxRequest,
            {
                "schema_version": SCHEMA_VERSION,
                "id": f"sandbox-request:{request['id']}",
                "tool_name": self._tool_name,
                "tool_version": self._tool_version,
                "image_digest": request["image_digest"],
                "artifact_kind": ArtifactKind.DERIVED,
                "input_ref": request["script_ref"],
                "arguments": {"finding_id": request["finding_id"], "kind": kind.value},
                "output_file_names": list(self._output_file_names),
                "resource_budget": request["resource_budget"],
                "timeout_seconds": min(
                    request["timeout_seconds"], request["resource_budget"]["timeout_seconds"]
                ),
            },
        )
        result = await self._sandbox.run(sandbox_request, cancellation)
        return self._poc(
            request,
            kind,
            _poc_status(result["status"]),
            _poc_result(result),
            run_log_ref=result["stdout_ref"] or result["stderr_ref"],
        )

    @staticmethod
    def _poc(
        request: ProofRequest,
        kind: PocKind,
        status: PocStatus,
        result: PocResult | None,
        *,
        run_log_ref: str | None = None,
    ) -> Poc:
        return cast(
            Poc,
            {
                "schema_version": SCHEMA_VERSION,
                "id": request["id"],
                "finding_id": request["finding_id"],
                "kind": kind,
                "status": status,
                "result": result,
                "script_ref": request["script_ref"],
                "run_log_ref": run_log_ref,
                "image_digest": request["image_digest"],
                "permission_mode": request["permission_mode"],
                "resource_budget": request["resource_budget"],
                "created_at": datetime.now(UTC).isoformat(),
            },
        )


def _poc_status(status: SandboxStatus) -> PocStatus:
    if status is SandboxStatus.SUCCEEDED:
        return PocStatus.COMPLETED
    if status is SandboxStatus.CANCELLED:
        return PocStatus.CANCELLED
    return PocStatus.FAILED


def _poc_result(result: SandboxResult) -> PocResult:
    status = result["status"]
    if status is SandboxStatus.SUCCEEDED:
        return PocResult.EXPLOITABLE
    if status is SandboxStatus.TIMED_OUT:
        return PocResult.TIMEOUT
    if status is SandboxStatus.POLICY_DENIED:
        return PocResult.POLICY_DENIED
    if status is SandboxStatus.CANCELLED:
        return PocResult.ENVIRONMENT_ERROR
    return PocResult.TOOL_ERROR
