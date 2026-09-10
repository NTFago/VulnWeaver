import asyncio
from typing import cast

import pytest
from vulnweaver_contracts import (
    FuzzRequest,
    JobKind,
    JobStatus,
    SandboxRequest,
    SchemaVersion,
)
from vulnweaver_fuzzing import FuzzJobExecutor, build_fuzz_request


class Service:
    async def run(self, _request, _cancellation):
        raise AssertionError("invalid jobs must not reach the fuzz service")


def _job(kind=JobKind.FUZZ, arguments=None):
    return {
        "schema_version": SchemaVersion.VALUE_1_0_0,
        "id": "job-fuzz",
        "task_id": "task",
        "kind": kind,
        "input_refs": [],
        "status": JobStatus.QUEUED,
        "idempotency_key": "key",
        "resource_budget": {
            "timeout_seconds": 1,
            "cpu_millis": 1000,
            "memory_bytes": 1048576,
            "disk_bytes": 1048576,
            "max_model_tokens": 0,
            "max_tool_concurrency": 1,
            "max_dynamic_runs": 1,
        },
        "retry_policy": {"max_attempts": 1, "backoff_seconds": 0, "retryable_failure_kinds": []},
        "attempt": 0,
        "lease": None,
        "failure": None,
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z",
        "arguments": arguments,
    }


@pytest.mark.anyio
async def test_fuzz_job_executor_rejects_missing_request():
    result = await FuzzJobExecutor(Service()).execute(_job(), asyncio.Event())
    assert result["status"] is JobStatus.FAILED
    assert result["failure"]["code"] == "fuzz.request_required"


@pytest.mark.anyio
async def test_fuzz_job_executor_rejects_other_job_kind():
    result = await FuzzJobExecutor(Service()).execute(_job(JobKind.REVIEW), asyncio.Event())
    assert result["failure"]["code"] == "fuzz.invalid_job_kind"


def test_build_fuzz_request_uses_only_fixed_sandbox_fields():
    request = build_fuzz_request(
        _job(),
        artifact_version_id="version",
        target_ref="sha256:target",
        seed_refs=["sha256:seed"],
        image_digest="sha256:" + "a" * 64,
        max_executions=10,
        max_duration_seconds=1,
        max_crashes=1,
    )
    assert request["job_id"] == "job-fuzz"
    assert request["sandbox_request"]["tool_name"] == "afl-casr"
    assert request["sandbox_request"]["arguments"] == {}


class _Sink:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    async def persist(self, *, finding_id, crashes, created_by):
        self.calls.append({"finding_id": finding_id, "created_by": created_by})
        return tuple(f"evidence:{index}" for index, _ in enumerate(crashes))


class _CrashingService:
    """Returns one crash so the evidence-linking path is exercised."""

    def __init__(self, *, crashes: bool = True) -> None:
        self._crashes = crashes

    async def run_with_crashes(self, request, _cancellation):
        from vulnweaver_contracts import FuzzStatus
        from vulnweaver_fuzzing import FuzzRunOutcome

        notice = _crash_record() if self._crashes else None
        return FuzzRunOutcome(
            result={
                "schema_version": "1.0.0",
                "job_id": request["job_id"],
                "status": FuzzStatus.SUCCEEDED,
                "executions": 1,
                "coverage_percent": None,
                "crash_ids": [notice["id"]] if notice else [],
                "failure": None,
                "created_at": "2026-01-01T00:00:00Z",
            },
            crashes=(notice,) if notice else (),
        )


def _crash_record():
    from vulnweaver_contracts import CrashRecord

    return cast(
        CrashRecord,
        {
            "schema_version": "1.0.0",
            "id": "crash:1",
            "artifact_version_id": "artifact-version:1",
            "input_ref": "cas://sha256/" + "b" * 64,
            "input_digest": "sha256:" + "b" * 64,
            "signal": "SIGSEGV",
            "exit_code": 11,
            "stack_frames": [],
            "stack_hash": "sha256:" + "c" * 64,
            "stderr_ref": None,
            "fuzz_tool": {"name": "afl-casr", "version": "1.0.0", "image_digest": None},
            "tool": {"name": "casr", "version": "2.12.0", "image_digest": None},
            "created_at": "2026-01-01T00:00:00Z",
        },
    )


def _bound_request(job_id: str = "job-fuzz") -> FuzzRequest:
    return cast(
        FuzzRequest,
        {
            "schema_version": "1.0.0",
            "id": f"fuzz-request:{job_id}",
            "job_id": job_id,
            "sandbox_request": _sandbox_request(),
            "artifact_version_id": "artifact-version:1",
            "seed_refs": ["cas://sha256/" + "e" * 64],
            "max_executions": 1,
            "max_duration_seconds": 1,
            "max_crashes": 1,
            "collect_coverage": False,
        },
    )


def _sandbox_request() -> SandboxRequest:
    return cast(
        SandboxRequest,
        {
            "schema_version": "1.0.0",
            "id": "sandbox-request:job-fuzz",
            "tool_name": "afl-casr",
            "tool_version": "1.0.0",
            "image_digest": "sha256:" + "a" * 64,
            "artifact_kind": "elf",
            "input_ref": "cas://sha256/" + "d" * 64,
            "arguments": {},
            "output_file_names": [],
            "resource_budget": {
                "max_model_tokens": 0,
                "cpu_millis": 1000,
                "memory_bytes": 1048576,
                "disk_bytes": 1048576,
                "max_tool_concurrency": 1,
                "max_dynamic_runs": 1,
                "timeout_seconds": 1,
            },
            "timeout_seconds": 1,
        },
    )


@pytest.mark.anyio
async def test_fuzz_job_executor_links_crashes_to_the_finding():
    sink = _Sink()
    executor = FuzzJobExecutor(_CrashingService(), crash_sink=sink)  # type: ignore[arg-type]

    result = await executor.execute(
        _job(arguments={"finding_id": "finding:1", "fuzz_request": _bound_request()}),
        asyncio.Event(),
    )

    assert result["status"] is JobStatus.SUCCEEDED
    assert result["evidence_ids"] == ["evidence:0"]
    assert sink.calls == [{"finding_id": "finding:1", "created_by": "job-fuzz"}]


@pytest.mark.anyio
async def test_fuzz_job_executor_reports_unlinked_crashes_instead_of_succeeding():
    """A reproducible crash that cannot be linked must not look like a clean run."""
    executor = FuzzJobExecutor(_CrashingService())  # type: ignore[arg-type]

    result = await executor.execute(
        _job(arguments={"finding_id": "finding:1", "fuzz_request": _bound_request()}),
        asyncio.Event(),
    )

    assert result["status"] is JobStatus.FAILED
    assert result["failure"]["code"] == "fuzz.crash_sink_unconfigured"


@pytest.mark.anyio
async def test_fuzz_job_executor_requires_a_finding_when_crashes_exist():
    sink = _Sink()
    executor = FuzzJobExecutor(_CrashingService(), crash_sink=sink)  # type: ignore[arg-type]

    result = await executor.execute(
        _job(arguments={"fuzz_request": _bound_request()}), asyncio.Event()
    )

    assert result["status"] is JobStatus.FAILED
    assert result["failure"]["code"] == "fuzz.crash_finding_required"
    assert sink.calls == []


@pytest.mark.anyio
async def test_fuzz_job_executor_succeeds_without_crashes():
    executor = FuzzJobExecutor(_CrashingService(crashes=False))  # type: ignore[arg-type]

    result = await executor.execute(
        _job(arguments={"finding_id": "finding:1", "fuzz_request": _bound_request()}),
        asyncio.Event(),
    )

    assert result["status"] is JobStatus.SUCCEEDED
    assert result["evidence_ids"] == []
