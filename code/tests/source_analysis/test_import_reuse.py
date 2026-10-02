"""Source-import index reuse: a second task adopts the deterministic index."""

from __future__ import annotations

import asyncio
import io
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from vulnweaver_artifact_store import LocalContentAddressedStore
from vulnweaver_contracts import (
    Job,
    JobKind,
    JobStatus,
    JsonObject,
    SchemaVersion,
)
from vulnweaver_persistence import Database, DatabaseSettings
from vulnweaver_persistence.models import job_results
from vulnweaver_source_analysis import SourceImportExecutor
from vulnweaver_source_analysis.static_executor import StaticAnalysisScheduler

from tests.persistence.factories import (
    artifact,
    artifact_version,
    project,
    task,
)
from tests.persistence.factories import (
    job as job_factory,
)
from tests.source_analysis.test_source_import import zip_bytes


class _SpyStaticScheduler:
    """Record schedule() calls instead of enqueuing real static Jobs."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    async def schedule(
        self, import_job: Job, source_result: JsonObject, source_version_id: str
    ) -> tuple[str, ...]:
        self.calls.append((import_job["id"], source_version_id))
        return ()


def _import_job(identifier: str, task_id: str, version_id: str, object_ref: str) -> Job:
    base = job_factory(
        identifier,
        task_id=task_id,
        idempotency_key=identifier + "-key",
        kind=JobKind.IMPORT,
    )
    base["tool"] = {"name": "source-import", "version": "1.0.0", "image_digest": None}
    base["arguments"] = {"artifact_version_id": version_id}
    base["input_refs"] = [object_ref]
    base["status"] = JobStatus.RUNNING
    return base


async def _seed(
    database: Database, suffix: str, object_ref: str
) -> tuple[str, str, str]:
    """One project + archive input; returns (version_id, task_id, project_id)."""

    version_id = f"artifact-version:{suffix}"
    async with database.transaction() as repositories:
        await repositories.projects.add(project(f"project:{suffix}"))
        await repositories.artifacts.add(
            artifact(
                f"artifact:{suffix}",
                project_id=f"project:{suffix}",
                current_version_id=version_id,
            )
        )
        await repositories.artifacts.add_version(
            artifact_version(version_id, artifact_id=f"artifact:{suffix}")
        )
        await repositories.tasks.create(
            task(
                f"task:{suffix}",
                project_id=f"project:{suffix}",
                artifact_version_ids=[version_id],
                idempotency_key=f"task:{suffix}-key",
            )
        )
    return version_id, f"task:{suffix}", f"project:{suffix}"


async def _settle_prior_import(database: Database, job: Job, produced: list[str]) -> None:
    succeeded = cast(Job, {**job, "status": JobStatus.SUCCEEDED})
    async with database.transaction() as repositories:
        await repositories.jobs.create_without_outbox(succeeded)
    async with database.engine.begin() as connection:
        await connection.execute(
            job_results.insert().values(
                job_id=job["id"],
                schema_version=SchemaVersion.VALUE_1_0_0,
                status="succeeded",
                produced_artifact_version_ids=produced,
                evidence_ids=[],
                failure=None,
                result_fingerprint="b" * 64,
                completed_at=datetime.now(UTC),
            )
        )


def test_source_executor_reuses_index_and_still_schedules_static_jobs(
    persistence_database_url: str, tmp_path: Path
) -> None:
    """A second task over the same archive adopts the index and re-runs scanners.

    Extraction and tree-sitter indexing are deterministic CPU work: the second
    import must not repeat them. Static-analysis Jobs are per-task evidence,
    so the spy scheduler must still be called -- with the REUSED index version
    id, because the scanners read the index document by reference.
    """

    async def scenario() -> None:
        marker = uuid.uuid4().hex[:12]
        database = Database(DatabaseSettings(persistence_database_url))
        store = LocalContentAddressedStore(tmp_path / "artifacts")
        archive = zip_bytes(
            {
                "src/main.c": b"int main(){return helper();}",
                "src/helper.c": b"int helper(){return 1;}\n",
            }
        ).getvalue()
        stored = store.put_stream(io.BytesIO(archive), max_bytes=len(archive))
        try:
            version_id, task_id, project_id = await _seed(
                database, f"src-reuse-a-{marker}", stored.object_ref
            )
            first_scheduler = _SpyStaticScheduler()
            first_executor = SourceImportExecutor(
                database,
                store,
                scratch_root=tmp_path,
                static_scheduler=cast(StaticAnalysisScheduler, first_scheduler),
            )
            first_job = _import_job(
                f"job:src-reuse-a-{marker}", task_id, version_id, stored.object_ref
            )
            first = await first_executor.execute(first_job, asyncio.Event())
            assert first["status"] is JobStatus.SUCCEEDED
            first_index_version = first["produced_artifact_version_ids"][0]
            assert first_scheduler.calls == [(first_job["id"], first_index_version)]
            await _settle_prior_import(database, first_job, [first_index_version])

            # A second task over the SAME input version, same project: this is
            # the re-run scenario reuse exists for (cross-project lookups are
            # excluded by design).
            second_suffix = f"src-reuse-b-{marker}"
            async with database.transaction() as repositories:
                await repositories.tasks.create(
                    task(
                        f"task:{second_suffix}",
                        project_id=project_id,
                        artifact_version_ids=[version_id],
                        idempotency_key=f"task:{second_suffix}-key",
                    )
                )
            second_scheduler = _SpyStaticScheduler()
            second_executor = SourceImportExecutor(
                database,
                store,
                scratch_root=tmp_path,
                static_scheduler=cast(StaticAnalysisScheduler, second_scheduler),
            )
            second_job = _import_job(
                f"job:{second_suffix}", f"task:{second_suffix}", version_id, stored.object_ref
            )
            second = await second_executor.execute(second_job, asyncio.Event())
            assert second["status"] is JobStatus.SUCCEEDED
            assert second["produced_artifact_version_ids"] == [first_index_version]
            assert second_scheduler.calls == [
                (second_job["id"], first_index_version)
            ], "static Jobs must be scheduled against the reused index"
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_source_executor_falls_back_without_a_matching_reuse_key(
    persistence_database_url: str, tmp_path: Path
) -> None:
    """An index produced under a different fingerprint is never adopted."""

    async def scenario() -> None:
        marker = uuid.uuid4().hex[:12]
        database = Database(DatabaseSettings(persistence_database_url))
        store = LocalContentAddressedStore(tmp_path / "artifacts")
        archive = zip_bytes({"src/main.c": b"int main(){return 0;}\n"}).getvalue()
        stored = store.put_stream(io.BytesIO(archive), max_bytes=len(archive))
        try:
            version_id, task_id, project_id = await _seed(
                database, f"src-miss-a-{marker}", stored.object_ref
            )
            first_scheduler = _SpyStaticScheduler()
            first_executor = SourceImportExecutor(
                database,
                store,
                scratch_root=tmp_path,
                static_scheduler=cast(StaticAnalysisScheduler, first_scheduler),
            )
            first_job = _import_job(
                f"job:src-miss-a-{marker}", task_id, version_id, stored.object_ref
            )
            first = await first_executor.execute(first_job, asyncio.Event())
            assert first["status"] is JobStatus.SUCCEEDED
            first_index_version = first["produced_artifact_version_ids"][0]

            from sqlalchemy import update
            from vulnweaver_persistence.models import artifact_versions

            async with database.engine.begin() as connection:
                await connection.execute(
                    update(artifact_versions)
                    .where(artifact_versions.c.id == first_index_version)
                    .values(
                        generation_config={
                            # The shape every index published before reuse keys
                            # existed: the lookup must never adopt it.
                            "format": "source-import-result",
                            "files": 1,
                            "schema_version": "1.0.0",
                        }
                    )
                )

            second_suffix = f"src-miss-b-{marker}"
            async with database.transaction() as repositories:
                await repositories.tasks.create(
                    task(
                        f"task:{second_suffix}",
                        project_id=project_id,
                        artifact_version_ids=[version_id],
                        idempotency_key=f"task:{second_suffix}-key",
                    )
                )
            second_scheduler = _SpyStaticScheduler()
            second_executor = SourceImportExecutor(
                database,
                store,
                scratch_root=tmp_path,
                static_scheduler=cast(StaticAnalysisScheduler, second_scheduler),
            )
            second_job = _import_job(
                f"job:{second_suffix}", f"task:{second_suffix}", version_id, stored.object_ref
            )
            second = await second_executor.execute(second_job, asyncio.Event())
            assert second["status"] is JobStatus.SUCCEEDED
            assert second["produced_artifact_version_ids"] != [first_index_version]
            assert second_scheduler.calls == [
                (second_job["id"], second["produced_artifact_version_ids"][0])
            ]
        finally:
            await database.dispose()

    asyncio.run(scenario())
