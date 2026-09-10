"""Build and execute proof requests without giving callers command access."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Protocol, cast

from vulnweaver_contracts import (
    SCHEMA_VERSION,
    ArtifactKind,
    FailureKind,
    FindingStatus,
    Job,
    JobKind,
    JobStatus,
    Poc,
    PocKind,
    PocResult,
    PocStatus,
    ProofRequest,
    ResourceBudget,
    SandboxRequest,
    SandboxResult,
    SandboxStatus,
    SchemaVersion,
    StructuredFailure,
    WorkerResult,
    validate_contract,
)
from vulnweaver_domain import evaluate_exploit_eligibility
from vulnweaver_persistence import Database
from vulnweaver_tool_runtime import bounded_resource_budget

from .auto_exploit import AutoExploitError, ExploitScriptGenerator
from .validation import ScriptRefOwnershipError, ensure_script_ref_belongs_to_project


class ProofSandbox(Protocol):
    async def run(self, request: SandboxRequest, cancellation: asyncio.Event) -> SandboxResult: ...


class ProofExecutionError(ValueError):
    """Raised when a proof request is malformed or its tool binding is unsafe."""


class ProofJobExecutor:
    """Adapt the proof service to the durable Worker execution contract."""

    def __init__(
        self,
        database: Database,
        service: ProofExecutionService,
        *,
        script_generator: ExploitScriptGenerator | None = None,
    ) -> None:
        self._database = database
        self._service = service
        self._script_generator = script_generator

    async def execute(self, job: Job, cancellation: asyncio.Event) -> WorkerResult:
        if job["kind"] not in {JobKind.PROOF, JobKind.EXPLOIT}:
            return _worker_failure(job, "proof.invalid_job_kind", FailureKind.VALIDATION)
        arguments = job.get("arguments")
        raw_request = arguments.get("proof_request") if isinstance(arguments, dict) else None
        raw_auto = arguments.get("auto_exploit") if isinstance(arguments, dict) else None
        kind = PocKind.EXPLOIT if job["kind"] is JobKind.EXPLOIT else PocKind.PROOF_OF_CONCEPT
        try:
            if isinstance(raw_auto, dict):
                if job["kind"] is not JobKind.EXPLOIT:
                    return _worker_failure(
                        job, "proof.auto_requires_exploit_kind", FailureKind.VALIDATION
                    )
                request = await self._prepare_auto_request(
                    job, cast(dict[str, object], raw_auto)
                )
            else:
                if not isinstance(raw_request, dict):
                    return _worker_failure(job, "proof.request_required", FailureKind.VALIDATION)
                request = cast(ProofRequest, raw_request)
            # The sandbox call must stay outside any database transaction so a
            # slow runner cannot pin a pooled connection for the whole timeout.
            async with self._database.transaction() as repositories:
                finding = await repositories.findings.get(request["finding_id"])
                finding_status = finding["status"]
                task = await repositories.tasks.get(finding["task_id"])
                project = await repositories.projects.get(task["project_id"])
                if not isinstance(raw_auto, dict):
                    await ensure_script_ref_belongs_to_project(
                        repositories, script_ref=request["script_ref"], project_id=project["id"]
                    )
                exploit_validation_enabled = project["exploit_validation_enabled"]
            poc = await self._service.run(
                request,
                finding_status=finding_status,
                exploit_validation_enabled=exploit_validation_enabled,
                cancellation=cancellation,
                kind=kind,
            )
            async with self._database.transaction() as repositories:
                await repositories.pocs.create(poc)
        except ScriptRefOwnershipError as error:
            return _worker_failure(
                job, "proof.script_ref_outside_project", FailureKind.POLICY, str(error)
            )
        except AutoExploitError as error:
            return _worker_failure(job, error.code, error.kind, error.code.replace("_", " "))
        except (ProofExecutionError, TypeError, ValueError) as error:
            return _worker_failure(job, "proof.invalid_request", FailureKind.VALIDATION, str(error))
        status = JobStatus.CANCELLED if poc["status"] is PocStatus.CANCELLED else (
            JobStatus.SUCCEEDED if poc["status"] is PocStatus.COMPLETED else JobStatus.FAILED
        )
        return WorkerResult(
            schema_version=SchemaVersion.VALUE_1_0_0,
            job_id=job["id"],
            status=status,
            produced_artifact_version_ids=[],
            evidence_ids=[],
            failure=None if status is not JobStatus.FAILED else StructuredFailure(
                code=f"proof.{poc['result'] or 'failed'}",
                kind=(
                    FailureKind.POLICY
                    if poc["result"] is PocResult.POLICY_DENIED
                    else FailureKind.TOOL
                ),
                message="proof execution did not complete successfully",
                retryable=False,
                details={},
            ),
        )

    async def _prepare_auto_request(
        self,
        job: Job,
        auto: dict[str, object],
    ) -> ProofRequest:
        """Validate policy, generate and register the script, build the request."""
        finding_id = auto.get("finding_id")
        image_digest = auto.get("image_digest")
        if not isinstance(finding_id, str) or not finding_id:
            raise AutoExploitError("auto_exploit.finding_id_required", FailureKind.VALIDATION)
        if not isinstance(image_digest, str) or not image_digest.startswith("sha256:"):
            raise AutoExploitError("auto_exploit.image_digest_required", FailureKind.VALIDATION)
        if self._script_generator is None:
            raise AutoExploitError("auto_exploit.model_unconfigured", FailureKind.DEPENDENCY)
        async with self._database.transaction() as repositories:
            finding = await repositories.findings.get(finding_id)
            task = await repositories.tasks.get(finding["task_id"])
            project = await repositories.projects.get(task["project_id"])
            if (
                finding["status"] is not FindingStatus.CONFIRMED
                or not project["exploit_validation_enabled"]
            ):
                raise AutoExploitError("auto_exploit.policy_denied", FailureKind.POLICY)
            permission_mode = project["permission_mode"]
        generated = await self._script_generator.generate(job, finding_id)
        budget = job["resource_budget"]
        return cast(
            ProofRequest,
            {
                "schema_version": SchemaVersion.VALUE_1_0_0,
                "id": f"poc:{job['id']}",
                "job_id": job["id"],
                "finding_id": finding_id,
                "script_ref": generated.script_ref,
                "image_digest": image_digest,
                "permission_mode": permission_mode,
                "resource_budget": dict(budget),
                "timeout_seconds": min(120, int(budget["timeout_seconds"])),
            },
        )


def _worker_failure(
    job: Job, code: str, kind: FailureKind, message: str = "proof job rejected"
) -> WorkerResult:
    return WorkerResult(
        schema_version=SchemaVersion.VALUE_1_0_0,
        job_id=job["id"],
        status=JobStatus.FAILED,
        produced_artifact_version_ids=[],
        evidence_ids=[],
        failure=StructuredFailure(
            code=code, kind=kind, message=message, retryable=False, details={}
        ),
    )


class ProofExecutionService:
    """Run one fixed proof/exploit tool through the Sandbox Runner."""

    def __init__(
        self,
        sandbox: ProofSandbox,
        *,
        tool_name: str,
        tool_version: str,
        output_file_names: tuple[str, ...] = ("result.json",),
        resource_limits: ResourceBudget | None = None,
    ) -> None:
        if not tool_name or not tool_version or not output_file_names:
            raise ValueError("proof tool identity and outputs are required")
        self._sandbox = sandbox
        self._tool_name = tool_name
        self._tool_version = tool_version
        self._output_file_names = output_file_names
        self._resource_limits = resource_limits

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

        # The Runner refuses a request whose budget exceeds the registered ToolSpec, so the
        # project budget carried by the request must be clamped to the proof tool's limits.
        budget = (
            bounded_resource_budget(request["resource_budget"], self._resource_limits)
            if self._resource_limits is not None
            else request["resource_budget"]
        )
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
                "resource_budget": budget,
                "timeout_seconds": min(request["timeout_seconds"], budget["timeout_seconds"]),
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
    if status == SandboxStatus.SUCCEEDED:
        return PocStatus.COMPLETED
    if status == SandboxStatus.CANCELLED:
        return PocStatus.CANCELLED
    return PocStatus.FAILED


def _poc_result(result: SandboxResult) -> PocResult:
    status = result["status"]
    if status == SandboxStatus.SUCCEEDED:
        return PocResult.EXPLOITABLE
    if status == SandboxStatus.TIMED_OUT:
        return PocResult.TIMEOUT
    if status == SandboxStatus.POLICY_DENIED:
        return PocResult.POLICY_DENIED
    if status == SandboxStatus.CANCELLED:
        return PocResult.ENVIRONMENT_ERROR
    return PocResult.TOOL_ERROR
