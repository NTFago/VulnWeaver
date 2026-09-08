from __future__ import annotations

import asyncio
import io
import json
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import cast

from vulnweaver_artifact_store import LocalContentAddressedStore
from vulnweaver_contracts import (
    Artifact,
    ArtifactKind,
    ArtifactVersion,
    Job,
    JobKind,
    JobStatus,
    SchemaVersion,
    SourceImportResult,
    StaticAnalysisDiagnostic,
    StaticToolStatus,
    ToolSpec,
)
from vulnweaver_persistence import Database, DatabaseSettings
from vulnweaver_source_analysis import (
    StaticAnalysisExecutor,
    StaticAnalysisScheduler,
    StaticToolOutput,
)

from tests.persistence.factories import artifact, artifact_version, project, task


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


class _DiagnosticAdapter:
    name = "semgrep"

    def run(
        self,
        _root: Path,
        *,
        timeout_seconds: int,
        max_output_bytes: int = 16 * 1024 * 1024,
    ) -> StaticToolOutput:
        del timeout_seconds, max_output_bytes
        return StaticToolOutput(
            self.name,
            "1.0.0",
            StaticToolStatus.SUCCEEDED,
            0,
            b"{}",
            b"",
        )

    def parse(
        self, _output: StaticToolOutput, *, artifact_version_id: str
    ) -> list[StaticAnalysisDiagnostic]:
        return [
            StaticAnalysisDiagnostic(
                tool_name=self.name,
                rule_id="rule:test",
                severity="medium",
                message="test finding",
                location={
                    "artifact_version_id": artifact_version_id,
                    "path": "src/app.py",
                    "start_line": 1,
                    "start_column": 1,
                    "end_line": 1,
                    "end_column": 2,
                },
                cwe_ids=["CWE-20"],
                properties={},
            )
        ]


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


def test_static_result_parent_matches_scanned_source_archive(
    persistence_database_url: str, tmp_path: Path
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        store = LocalContentAddressedStore(tmp_path / "artifacts")
        try:
            archive_bytes = io.BytesIO()
            with zipfile.ZipFile(archive_bytes, "w") as archive:
                archive.writestr("src/app.py", "value = input()")
            payload = archive_bytes.getvalue()
            stored = store.put_stream(io.BytesIO(payload), max_bytes=len(payload))
            async with database.transaction() as repositories:
                await repositories.projects.add(project("project:static-lineage"))
                await repositories.artifacts.add(
                    artifact(
                        "artifact:static-lineage",
                        project_id="project:static-lineage",
                        current_version_id="artifact-version:static-source",
                    )
                )
                await repositories.artifacts.add_version(
                    artifact_version(
                        "artifact-version:static-source",
                        artifact_id="artifact:static-lineage",
                        digest_character="1",
                    )
                )
                await repositories.artifacts.add(
                    cast(
                        Artifact,
                        {
                            **artifact(
                                "artifact:static-index",
                                project_id="project:static-lineage",
                                current_version_id="artifact-version:static-index",
                            ),
                            "kind": ArtifactKind.DERIVED,
                        },
                    )
                )
                await repositories.artifacts.add_version(
                    cast(
                        ArtifactVersion,
                        {
                            **artifact_version(
                                "artifact-version:static-index",
                                artifact_id="artifact:static-index",
                                digest_character="2",
                            ),
                            "parent_version_id": "artifact-version:static-source",
                        },
                    )
                )
                await repositories.tasks.create(
                    task(
                        "task:static-lineage",
                        project_id="project:static-lineage",
                        artifact_version_ids=["artifact-version:static-source"],
                    )
                )

            job = cast(
                Job,
                {
                    **_import_job(),
                    "id": "job:static-lineage",
                    "task_id": "task:static-lineage",
                    "kind": JobKind.SOURCE_ANALYSIS,
                    "tool": {
                        "name": "semgrep",
                        "version": "1.0.0",
                        "image_digest": "sha256:" + "3" * 64,
                    },
                    "arguments": {
                        "artifact_version_id": "artifact-version:static-source",
                        "source_index_version_id": "artifact-version:static-index",
                        "languages": ["python"],
                    },
                    "input_refs": [stored.object_ref],
                },
            )
            executor = StaticAnalysisExecutor(
                database,
                store,
                adapters={"semgrep": _DiagnosticAdapter()},
                scratch_root=tmp_path,
            )
            result = await executor.execute(job, asyncio.Event())

            assert result["status"] is JobStatus.SUCCEEDED
            async with database.transaction() as repositories:
                version = await repositories.artifacts.get_version(
                    result["produced_artifact_version_ids"][0]
                )
                assert version["parent_version_id"] == "artifact-version:static-source"
                assert (
                    version["generation_config"]["source_index_version_id"]
                    == "artifact-version:static-index"
                )
                with store.open(version["object_ref"]) as stream:
                    document = json.load(stream)
                assert (
                    document["diagnostics"][0]["location"]["artifact_version_id"]
                    == version["parent_version_id"]
                )
        finally:
            await database.dispose()

    asyncio.run(scenario())
