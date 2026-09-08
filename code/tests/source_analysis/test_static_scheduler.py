from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import cast

from vulnweaver_contracts import (
    Job,
    JobKind,
    JobStatus,
    SchemaVersion,
    SourceImportResult,
    ToolSpec,
)
from vulnweaver_persistence import Database
from vulnweaver_source_analysis import StaticAnalysisScheduler


class _FakeTransaction:
    def __init__(self, repositories: object) -> None:
        self._repositories = repositories

    async def __aenter__(self) -> object:
        return self._repositories

    async def __aexit__(self, *_args: object) -> None:
        return None


class _FakeJobs:
    def __init__(self) -> None:
        self.jobs: list[Job] = []
        self.events: list[object] = []

    async def enqueue_with_outbox(self, job: Job, event: object) -> None:
        self.jobs.append(job)
        self.events.append(event)


class _FakeDatabase:
    def __init__(self) -> None:
        self.jobs = _FakeJobs()
        self.repositories = SimpleNamespace(jobs=self.jobs)

    def transaction(self) -> _FakeTransaction:
        return _FakeTransaction(self.repositories)


def _tool_spec(name: str) -> dict[str, object]:
    return {
        "schema_version": "1.0.0",
        "name": name,
        "version": "1.0.0",
        "image_digest": "sha256:" + "a" * 64,
        "risk_level": "low",
        "accepted_artifacts": ["source_archive"],
        "command_schema": {"type": "object"},
        "output_schema": {"type": "object"},
        "network_policy": {"access": "none", "allowed_hosts": []},
        "filesystem_policy": {
            "input_read_only": True,
            "isolated_output": True,
            "allow_host_paths": False,
        },
        "resource_limits": {
            "max_model_tokens": 0,
            "cpu_millis": 1000,
            "memory_bytes": 1024,
            "disk_bytes": 1024,
            "max_tool_concurrency": 1,
            "max_dynamic_runs": 0,
            "timeout_seconds": 30,
        },
        "approval_required": False,
        "timeout_seconds": 30,
        "retry_policy": {
            "max_attempts": 2,
            "backoff_seconds": 1.0,
            "retryable_failure_kinds": [],
        },
    }


def _import_job() -> Job:
    return cast(
        Job,
        {
            "schema_version": SchemaVersion.VALUE_1_0_0,
            "id": "job:import",
            "task_id": "task:static",
            "kind": JobKind.IMPORT,
            "tool": {
                "name": "source-import",
                "version": "1.0.0",
                "image_digest": "sha256:" + "b" * 64,
            },
            "arguments": {"artifact_version_id": "artifact-version:source"},
            "input_refs": ["sha256:archive"],
            "status": JobStatus.RUNNING,
            "idempotency_key": "job:import:key",
            "resource_budget": _tool_spec("semgrep")["resource_limits"],
            "retry_policy": _tool_spec("semgrep")["retry_policy"],
            "attempt": 1,
            "lease": None,
            "failure": None,
            "created_at": "2026-09-08T10:00:00Z",
            "updated_at": "2026-09-08T10:00:00Z",
        },
    )


def test_scheduler_creates_capability_selected_jobs_idempotently() -> None:
    async def scenario() -> None:
        database = _FakeDatabase()
        scheduler = StaticAnalysisScheduler(
            cast(Database, database),
            {
                "semgrep": cast(ToolSpec, _tool_spec("semgrep")),
                "cppcheck": cast(ToolSpec, _tool_spec("cppcheck")),
            },
            clock=lambda: datetime(2026, 9, 8, 10, tzinfo=UTC),
        )
        result = cast(
            SourceImportResult,
            {
                "schema_version": SchemaVersion.VALUE_1_0_0,
                "artifact_version_id": "artifact-version:source",
                "files": [],
                "functions": [],
                "calls": [],
                "capability_profile": {
                    "schema_version": SchemaVersion.VALUE_1_0_0,
                    "artifact_version_id": "artifact-version:source",
                    "languages": ["python", "cpp"],
                    "architectures": [],
                    "build_systems": [],
                    "capabilities": [],
                    "created_at": "2026-09-08T10:00:00Z",
                },
            },
        )

        scheduled = await scheduler.schedule(_import_job(), result, "artifact-version:index")

        assert len(scheduled) == 2
        assert {job["id"] for job in database.jobs.jobs} == set(scheduled)
        assert {job["tool"]["name"] for job in database.jobs.jobs} == {
            "semgrep",
            "cppcheck",
        }
        assert all(job["kind"] is JobKind.SOURCE_ANALYSIS for job in database.jobs.jobs)
        assert all(
            job["arguments"]["source_index_version_id"] == "artifact-version:index"
            for job in database.jobs.jobs
        )
        assert len(database.jobs.events) == 2

    asyncio.run(scenario())
