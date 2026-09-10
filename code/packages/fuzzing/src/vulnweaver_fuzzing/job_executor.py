"""Adapt a validated fuzz request to the durable worker contract."""
from __future__ import annotations

import asyncio
from typing import cast

from vulnweaver_contracts import (
    ArtifactKind,
    FailureKind,
    FuzzRequest,
    FuzzStatus,
    Job,
    JobKind,
    JobStatus,
    ResourceBudget,
    SandboxRequest,
    SchemaVersion,
    StructuredFailure,
    WorkerResult,
    validate_contract,
)

from vulnweaver_fuzzing.executor import FuzzExecutionService


class FuzzJobExecutor:
    """Execute only an explicitly structured FuzzRequest attached to a fuzz Job."""

    def __init__(self, service: FuzzExecutionService) -> None:
        self._service = service

    async def execute(self, job: Job, cancellation: asyncio.Event) -> WorkerResult:
        if job["kind"] is not JobKind.FUZZ:
            return _failed(job, "fuzz.invalid_job_kind", FailureKind.VALIDATION)
        arguments = job.get("arguments")
        raw = arguments.get("fuzz_request") if isinstance(arguments, dict) else None
        if not isinstance(raw, dict):
            return _failed(job, "fuzz.request_required", FailureKind.VALIDATION)
        request = cast(FuzzRequest, raw)
        if request.get("job_id") != job["id"]:
            return _failed(job, "fuzz.job_id_mismatch", FailureKind.VALIDATION)
        try:
            validate_contract("FuzzRequest", request)
            result = await self._service.run(request, cancellation)
        except (TypeError, ValueError) as error:
            return _failed(job, "fuzz.invalid_request", FailureKind.VALIDATION, str(error))
        if result["status"] is FuzzStatus.SUCCEEDED:
            status, failure = JobStatus.SUCCEEDED, None
        elif result["status"] is FuzzStatus.CANCELLED:
            status, failure = JobStatus.CANCELLED, result["failure"]
        else:
            status, failure = JobStatus.FAILED, result["failure"]
        return WorkerResult(
            schema_version=SchemaVersion.VALUE_1_0_0,
            job_id=job["id"],
            status=status,
            produced_artifact_version_ids=[],
            evidence_ids=[],
            failure=failure,
        )


def _failed(
    job: Job, code: str, kind: FailureKind, message: str = "fuzz job rejected"
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


def build_fuzz_request(
    job: Job,
    *,
    artifact_version_id: str,
    target_ref: str,
    seed_refs: list[str],
    image_digest: str,
    max_executions: int,
    max_duration_seconds: int,
    max_crashes: int,
    collect_coverage: bool = True,
) -> FuzzRequest:
    """Build the fixed request shape without accepting executable commands."""
    if job["kind"] is not JobKind.FUZZ:
        raise ValueError("only fuzz Jobs can construct fuzz requests")
    if not all((artifact_version_id, target_ref, image_digest)) or not seed_refs:
        raise ValueError("fuzz target, artifact version, image digest and seeds are required")
    budget = cast(ResourceBudget, dict(job["resource_budget"]))
    request = FuzzRequest(
        schema_version=SchemaVersion.VALUE_1_0_0,
        id=f"fuzz-request:{job['id']}",
        job_id=job["id"],
        sandbox_request=SandboxRequest(
            schema_version=SchemaVersion.VALUE_1_0_0,
            id=f"sandbox-request:{job['id']}",
            tool_name="afl-casr",
            tool_version="1.0.0",
            image_digest=image_digest,
            artifact_kind=ArtifactKind.ELF,
            input_ref=target_ref,
            arguments={},
            output_file_names=[],
            resource_budget=budget,
            timeout_seconds=min(budget["timeout_seconds"], max_duration_seconds),
        ),
        artifact_version_id=artifact_version_id,
        seed_refs=seed_refs,
        max_executions=max_executions,
        max_duration_seconds=max_duration_seconds,
        max_crashes=max_crashes,
        collect_coverage=collect_coverage,
    )
    validate_contract("FuzzRequest", request)
    return request
