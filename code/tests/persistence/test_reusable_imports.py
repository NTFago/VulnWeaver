"""Query contract of the reusable-import lookup (import result cache)."""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta

from vulnweaver_contracts import JobKind, JobStatus, SchemaVersion
from vulnweaver_persistence import Database, DatabaseSettings
from vulnweaver_persistence.models import job_results

from tests.persistence.factories import (
    artifact,
    artifact_version,
    project,
    task,
)
from tests.persistence.factories import (
    job as job_factory,
)

_SEED_CLOCK = datetime(2026, 10, 2, 12, 0, 0, tzinfo=UTC)


async def _seed_pipeline(
    database: Database,
    suffix: str,
    *,
    object_ref: str,
    tool_name: str,
    status: JobStatus,
    produced: list[str] | None,
) -> None:
    """One project, artifact, task, import Job and (optionally) its result."""

    global _SEED_CLOCK
    _SEED_CLOCK = _SEED_CLOCK + timedelta(seconds=1)
    created_at = _SEED_CLOCK.isoformat()

    async with database.transaction() as repositories:
        await repositories.projects.add(project(f"project:{suffix}"))
        await repositories.artifacts.add(
            artifact(
                f"artifact:{suffix}",
                project_id=f"project:{suffix}",
                current_version_id=f"artifact-version:{suffix}",
            )
        )
        await repositories.artifacts.add_version(
            artifact_version(
                f"artifact-version:{suffix}",
                artifact_id=f"artifact:{suffix}",
            )
        )
        await repositories.tasks.create(
            task(
                f"task:{suffix}",
                project_id=f"project:{suffix}",
                artifact_version_ids=["artifact-version:" + suffix],
                idempotency_key=f"task:{suffix}-key",
            )
        )
    candidate = job_factory(
        f"job:{suffix}",
        task_id=f"task:{suffix}",
        idempotency_key=f"job:{suffix}-key",
        kind=JobKind.IMPORT,
    )
    candidate["tool"] = {"name": tool_name, "version": "1.0.0", "image_digest": None}
    candidate["input_refs"] = [object_ref]
    candidate["status"] = status
    candidate["created_at"] = created_at
    candidate["updated_at"] = created_at
    async with database.transaction() as repositories:
        await repositories.jobs.create_without_outbox(candidate)
    if produced is None:
        return
    async with database.engine.begin() as connection:
        await connection.execute(
            job_results.insert().values(
                job_id=candidate["id"],
                schema_version=SchemaVersion.VALUE_1_0_0,
                status=JobStatus.SUCCEEDED.value,
                produced_artifact_version_ids=produced,
                evidence_ids=[],
                failure=None,
                result_fingerprint="f" * 64,
                completed_at=datetime.now(UTC),
            )
        )


def test_reusable_imports_match_project_tool_and_status(
    persistence_database_url: str,
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        marker = uuid.uuid4().hex[:12]
        object_ref = f"cas://sha256/{'1' * 64}"
        produced = [f"artifact-version:derived-{marker}"]
        await _seed_pipeline(
            database,
            f"hit-{marker}",
            object_ref=object_ref,
            tool_name="binary-import",
            status=JobStatus.SUCCEEDED,
            produced=produced,
        )
        # Same input in another project: must not leak across the scope.
        await _seed_pipeline(
            database,
            f"other-{marker}",
            object_ref=object_ref,
            tool_name="binary-import",
            status=JobStatus.SUCCEEDED,
            produced=[f"artifact-version:derived-other-{marker}"],
        )
        try:
            async with database.transaction() as repositories:
                hits = await repositories.jobs.find_reusable_imports(
                    object_ref, tool_name="binary-import", project_id=f"project:hit-{marker}"
                )
                assert [item.produced_artifact_version_ids for item in hits] == [tuple(produced)]
                assert hits[0].job_id == f"job:hit-{marker}"
                assert hits[0].task_id == f"task:hit-{marker}"

                other = await repositories.jobs.find_reusable_imports(
                    object_ref, tool_name="binary-import", project_id=f"project:other-{marker}"
                )
                assert [item.job_id for item in other] == [f"job:other-{marker}"]

                wrong_tool = await repositories.jobs.find_reusable_imports(
                    object_ref, tool_name="source-import", project_id=f"project:hit-{marker}"
                )
                assert wrong_tool == []
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_reusable_imports_ignore_running_and_resultless_jobs(
    persistence_database_url: str,
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        marker = uuid.uuid4().hex[:12]
        object_ref = f"cas://sha256/{'2' * 64}"
        # Still running: no terminal result to adopt.
        await _seed_pipeline(
            database,
            f"running-{marker}",
            object_ref=object_ref,
            tool_name="binary-import",
            status=JobStatus.RUNNING,
            produced=None,
        )
        # Succeeded but produced nothing.
        await _seed_pipeline(
            database,
            f"empty-{marker}",
            object_ref=object_ref,
            tool_name="binary-import",
            status=JobStatus.SUCCEEDED,
            produced=[],
        )
        try:
            async with database.transaction() as repositories:
                assert (
                    await repositories.jobs.find_reusable_imports(
                        object_ref,
                        tool_name="binary-import",
                        project_id=f"project:running-{marker}",
                    )
                    == []
                )
                assert (
                    await repositories.jobs.find_reusable_imports(
                        object_ref,
                        tool_name="binary-import",
                        project_id=f"project:empty-{marker}",
                    )
                    == []
                )
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_reusable_imports_newest_first(persistence_database_url: str) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        marker = uuid.uuid4().hex[:12]
        object_ref = f"cas://sha256/{'4' * 64}"
        await _seed_pipeline(
            database,
            f"old-{marker}",
            object_ref=object_ref,
            tool_name="source-import",
            status=JobStatus.SUCCEEDED,
            produced=[f"artifact-version:index-old-{marker}"],
        )
        # A second task over the same input inside the SAME project, settling
        # later: the lookup must prefer it as the freshest adoptable result.
        version_id = f"artifact-version:old-{marker}"
        async with database.transaction() as repositories:
            await repositories.tasks.create(
                task(
                    f"task:new-{marker}",
                    project_id=f"project:old-{marker}",
                    artifact_version_ids=[version_id],
                    idempotency_key=f"task:new-{marker}-key",
                )
            )
        newer = job_factory(
            f"job:new-{marker}",
            task_id=f"task:new-{marker}",
            idempotency_key=f"job:new-{marker}-key",
            kind=JobKind.IMPORT,
        )
        newer["tool"] = {"name": "source-import", "version": "1.0.0", "image_digest": None}
        newer["input_refs"] = [object_ref]
        newer["status"] = JobStatus.SUCCEEDED
        newer["created_at"] = (_SEED_CLOCK + timedelta(seconds=60)).isoformat()
        newer["updated_at"] = newer["created_at"]
        async with database.transaction() as repositories:
            await repositories.jobs.create_without_outbox(newer)
        async with database.engine.begin() as connection:
            await connection.execute(
                job_results.insert().values(
                    job_id=newer["id"],
                    schema_version=SchemaVersion.VALUE_1_0_0,
                    status=JobStatus.SUCCEEDED.value,
                    produced_artifact_version_ids=[f"artifact-version:index-new-{marker}"],
                    evidence_ids=[],
                    failure=None,
                    result_fingerprint="f" * 64,
                    completed_at=datetime.now(UTC),
                )
            )
        try:
            async with database.transaction() as repositories:
                hits = await repositories.jobs.find_reusable_imports(
                    object_ref, tool_name="source-import", project_id=f"project:old-{marker}"
                )
                assert [item.job_id for item in hits] == [
                    f"job:new-{marker}",
                    f"job:old-{marker}",
                ]
        finally:
            await database.dispose()

    asyncio.run(scenario())
