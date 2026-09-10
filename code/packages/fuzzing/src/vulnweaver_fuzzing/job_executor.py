"""Adapt a validated fuzz request to the durable worker contract."""
from __future__ import annotations

import asyncio
from typing import Protocol, cast

from vulnweaver_contracts import (
    ArtifactKind,
    CrashRecord,
    FailureKind,
    FuzzRequest,
    FuzzStatus,
    Job,
    JobKind,
    JobStatus,
    JsonObject,
    ResourceBudget,
    SandboxRequest,
    SchemaVersion,
    StructuredFailure,
    WorkerResult,
    validate_contract,
)

from vulnweaver_fuzzing.executor import FuzzExecutionService
from vulnweaver_fuzzing.harness_pipeline import HarnessPipeline


class CrashEvidenceSink(Protocol):
    async def persist(
        self, *, finding_id: str, crashes: tuple[CrashRecord, ...], created_by: str
    ) -> tuple[str, ...]: ...


class FuzzJobExecutor:
    """Execute only an explicitly structured FuzzRequest attached to a fuzz Job."""

    def __init__(
        self,
        service: FuzzExecutionService,
        *,
        crash_sink: CrashEvidenceSink | None = None,
        harness_pipeline: HarnessPipeline | None = None,
    ) -> None:
        self._service = service
        self._crash_sink = crash_sink
        self._harness_pipeline = harness_pipeline

    async def execute(self, job: Job, cancellation: asyncio.Event) -> WorkerResult:
        if job["kind"] is not JobKind.FUZZ:
            return _failed(job, "fuzz.invalid_job_kind", FailureKind.VALIDATION)
        arguments = job.get("arguments")
        if not isinstance(arguments, dict):
            return _failed(job, "fuzz.request_required", FailureKind.VALIDATION)
        raw = arguments.get("fuzz_request")
        if not isinstance(raw, dict):
            return _failed(job, "fuzz.request_required", FailureKind.VALIDATION)
        request = cast(FuzzRequest, raw)
        if request.get("job_id") != job["id"]:
            return _failed(job, "fuzz.job_id_mismatch", FailureKind.VALIDATION)
        finding_id = arguments.get("finding_id")
        try:
            validate_contract("FuzzRequest", request)
            harness_context = arguments.get("harness_context")
            if isinstance(harness_context, dict):
                if self._harness_pipeline is None:
                    return _failed(job, "fuzz.harness_unconfigured", FailureKind.DEPENDENCY)
                fixture_refs = arguments.get("harness_fixture_refs", [])
                if not isinstance(fixture_refs, list) or not all(
                    isinstance(item, str) for item in fixture_refs
                ):
                    return _failed(job, "fuzz.harness_fixtures_invalid", FailureKind.VALIDATION)
                built = await self._harness_pipeline.build(
                    task_id=job["task_id"],
                    job_id=job["id"],
                    artifact_version_id=request["artifact_version_id"],
                    context=cast(JsonObject, harness_context),
                    budget=cast(ResourceBudget, dict(job["resource_budget"])),
                    fixtures=tuple(cast(list[str], fixture_refs)),
                )
                if not built.succeeded:
                    return _failed(
                        job,
                        f"fuzz.harness_{built.status}",
                        FailureKind.DEPENDENCY,
                        "bounded fuzz harness generation or compilation failed",
                    )
                request = cast(
                    FuzzRequest,
                    {
                        **request,
                        "sandbox_request": {
                            **request["sandbox_request"],
                            "input_ref": built.compiled_ref,
                            "artifact_kind": ArtifactKind.ELF,
                        },
                    },
                )
                validate_contract("FuzzRequest", request)
            outcome = await self._service.run_with_crashes(request, cancellation)
            result = outcome.result
        except (TypeError, ValueError) as error:
            return _failed(job, "fuzz.invalid_request", FailureKind.VALIDATION, str(error))
        evidence_ids: list[str] = []
        if outcome.crashes:
            # A crash that cannot be linked is a loss of evidence, not a success:
            # reporting SUCCEEDED here would hide reproducible crashes from review.
            if self._crash_sink is None:
                return _unlinked(job, "fuzz.crash_sink_unconfigured")
            if not isinstance(finding_id, str):
                return _unlinked(job, "fuzz.crash_finding_required")
            try:
                evidence_ids = list(
                    await self._crash_sink.persist(
                        finding_id=finding_id, crashes=outcome.crashes, created_by=job["id"]
                    )
                )
            except (TypeError, ValueError) as error:
                return _failed(
                    job, "fuzz.crash_evidence_rejected", FailureKind.DEPENDENCY, str(error)
                )
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
            evidence_ids=evidence_ids,
            failure=failure,
        )


def _unlinked(job: Job, code: str) -> WorkerResult:
    return _failed(
        job,
        code,
        FailureKind.DEPENDENCY,
        "fuzz crashes were found but could not be attached to a Finding",
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
