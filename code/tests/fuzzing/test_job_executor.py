import asyncio

import pytest
from vulnweaver_contracts import JobKind, JobStatus, SchemaVersion
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
