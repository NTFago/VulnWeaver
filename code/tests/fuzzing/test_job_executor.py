import asyncio

import pytest
from vulnweaver_contracts import JobKind, JobStatus, SchemaVersion
from vulnweaver_fuzzing import FuzzJobExecutor


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
            "cpu_millis": 1,
            "memory_bytes": 1,
            "disk_bytes": 1,
            "max_model_tokens": 0,
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
