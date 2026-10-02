"""Import-result reuse: a second task over the same input adopts the prior run."""

from __future__ import annotations

import asyncio
import io
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from sqlalchemy import update
from vulnweaver_artifact_store import LocalContentAddressedStore
from vulnweaver_binary_analysis import BinaryImportExecutor, UpxCliUnpacker
from vulnweaver_contracts import (
    Artifact,
    ArtifactKind,
    ArtifactVersion,
    Job,
    JobKind,
    JobStatus,
    Project,
    ResourceBudget,
    Task,
    TaskStatus,
)
from vulnweaver_pair import BinaryPairImporter
from vulnweaver_persistence import Database, DatabaseSettings
from vulnweaver_persistence.models import artifact_versions, job_results

from tests.binary_analysis.samples import elf64_sample
from tests.binary_analysis.test_executor import _RecordingSandbox, _UnpacksUpx
from tests.persistence.factories import TIMESTAMP, budget


def _job(identifier: str, task_id: str, version_id: str, object_ref: str) -> Job:
    return Job(
        schema_version="1.0.0",
        id=identifier,
        task_id=task_id,
        kind=JobKind.IMPORT,
        tool={
            "name": "binary-import",
            "version": "1.0.0",
            "image_digest": "sha256:" + "a" * 64,
        },
        arguments={"artifact_version_id": version_id},
        input_refs=[object_ref],
        status=JobStatus.RUNNING,
        idempotency_key=identifier + "-key",
        resource_budget=cast(ResourceBudget, budget()),
        retry_policy={
            "max_attempts": 2,
            "backoff_seconds": 1.0,
            "retryable_failure_kinds": ["environment"],
        },
        attempt=1,
        lease=None,
        failure=None,
        created_at=TIMESTAMP,
        updated_at=TIMESTAMP,
    )


async def _seed_input(
    database: Database,
    store: LocalContentAddressedStore,
    tmp_path: Path,
    suffix: str,
) -> tuple[Job, str]:
    """Register one project + PE input and return its first import Job."""

    project_id = f"project:reuse-{suffix}"
    artifact_id = f"artifact:reuse-{suffix}"
    version_id = f"artifact-version:reuse-{suffix}"
    task_id = f"task:reuse-{suffix}"
    stored = store.put_stream(io.BytesIO(elf64_sample()), max_bytes=1024 * 1024)
    async with database.transaction() as repositories:
        await repositories.projects.add(
            Project(
                schema_version="1.0.0",
                id=project_id,
                name="Reuse project",
                input_scope=["local://authorized-binary"],
                permission_mode="request_permission",
                exploit_validation_enabled=False,
                resource_budget=cast(ResourceBudget, budget()),
                created_at=TIMESTAMP,
            )
        )
        await repositories.artifacts.add(
            Artifact(
                schema_version="1.0.0",
                id=artifact_id,
                project_id=project_id,
                kind=ArtifactKind.ELF,
                current_version_id=version_id,
                created_at=TIMESTAMP,
            )
        )
        await repositories.artifacts.add_version(
            ArtifactVersion(
                schema_version="1.0.0",
                id=version_id,
                artifact_id=artifact_id,
                digest=stored.digest,
                object_ref=stored.object_ref,
                generation_config={},
                created_at=TIMESTAMP,
            )
        )
        await repositories.tasks.create(
            Task(
                schema_version="1.0.0",
                id=task_id,
                project_id=project_id,
                artifact_version_ids=[version_id],
                status=TaskStatus.CREATED,
                result=None,
                failure=None,
                idempotency_key=f"task-reuse-{suffix}",
                resource_budget=cast(ResourceBudget, budget()),
                created_at=TIMESTAMP,
                updated_at=TIMESTAMP,
            )
        )
    return _job(f"job:reuse-{suffix}", task_id, version_id, stored.object_ref), version_id


async def _settle_prior_import(database: Database, job: Job, produced: list[str]) -> None:
    """Record a prior import as succeeded with a durable result row.

    Production settles through ``JobRepository.complete``; the reuse lookup
    only reads the same two durable facts this seeds (terminal job row and
    its job_results row).
    """

    succeeded = cast(
        Job, {**job, "status": JobStatus.SUCCEEDED, "updated_at": TIMESTAMP}
    )
    async with database.transaction() as repositories:
        await repositories.jobs.create_without_outbox(succeeded)
    async with database.engine.begin() as connection:
        await connection.execute(
            job_results.insert().values(
                job_id=job["id"],
                schema_version="1.0.0",
                status="succeeded",
                produced_artifact_version_ids=produced,
                evidence_ids=[],
                failure=None,
                result_fingerprint="a" * 64,
                completed_at=datetime.now(UTC),
            )
        )


def _executor(
    database: Database,
    store: LocalContentAddressedStore,
    tmp_path: Path,
    sandbox: _RecordingSandbox,
) -> BinaryImportExecutor:
    return BinaryImportExecutor(
        database,
        store,
        adapters=(),
        unpackers=(UpxCliUnpacker(upx=_UnpacksUpx()),),
        pair_importer=BinaryPairImporter(database),
        scratch_root=tmp_path,
        sandbox=sandbox,
        sandbox_image_digest="sha256:" + "a" * 64,
    )


def test_binary_executor_adopts_prior_result_for_identical_input(
    persistence_database_url: str, tmp_path: Path
) -> None:
    """A second task over the same upload reuses the analysis instead of redoing it.

    The facts chain (Ghidra over a real-world binary takes minutes) must run
    once per distinct input: the first run's produced versions are immutable
    and already carry their PAIR rows, so the second import adopts them
    verbatim -- zero sandbox runs, zero new versions.
    """

    async def scenario() -> None:
        suffix = uuid.uuid4().hex[:12]
        database = Database(DatabaseSettings(persistence_database_url))
        store = LocalContentAddressedStore(tmp_path / "store")
        try:
            first_job, _ = await _seed_input(database, store, tmp_path, suffix)
            first_sandbox = _RecordingSandbox(store)
            first = await _executor(database, store, tmp_path, first_sandbox).execute(
                first_job, asyncio.Event()
            )
            assert first["status"] is JobStatus.SUCCEEDED
            first_versions = list(first["produced_artifact_version_ids"])
            assert first_sandbox.requests, "the first run must analyse through the sandbox"
            await _settle_prior_import(database, first_job, first_versions)

            second_suffix = f"reuse-second-{uuid.uuid4().hex[:12]}"
            # The second task lives in the same project as the first input.
            async with database.transaction() as repositories:
                first_task = await repositories.tasks.get(first_job["task_id"])
                input_ids = list(first_task["artifact_version_ids"])
                await repositories.tasks.create(
                    Task(
                        schema_version="1.0.0",
                        id=f"task:{second_suffix}",
                        project_id=first_task["project_id"],
                        artifact_version_ids=input_ids,
                        status=TaskStatus.CREATED,
                        result=None,
                        failure=None,
                        idempotency_key=f"task-{second_suffix}-key",
                        resource_budget=cast(ResourceBudget, budget()),
                        created_at=TIMESTAMP,
                        updated_at=TIMESTAMP,
                    )
                )
            second_job = cast(
                Job,
                {
                    **first_job,
                    "id": f"job:{second_suffix}",
                    "task_id": f"task:{second_suffix}",
                    "idempotency_key": f"job-{second_suffix}-key",
                },
            )
            # Fails the test if the reuse path ever touches the tools.
            untouchable = _RecordingSandbox(store)
            second = await _executor(database, store, tmp_path, untouchable).execute(
                second_job, asyncio.Event()
            )
            assert second["status"] is JobStatus.SUCCEEDED
            assert not untouchable.requests, "a reused import must not re-run the tools"
            assert list(second["produced_artifact_version_ids"]) == first_versions
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_binary_executor_reruns_when_reuse_key_differs(
    persistence_database_url: str, tmp_path: Path
) -> None:
    """A prior result without a matching fingerprint never gets adopted.

    Versions produced before reuse keys existed carry no ``reuse_key``; a
    fingerprint mismatch (or its absence) must fall through to a full run.
    """

    async def scenario() -> None:
        suffix = uuid.uuid4().hex[:12]
        database = Database(DatabaseSettings(persistence_database_url))
        store = LocalContentAddressedStore(tmp_path / "store")
        try:
            first_job, _ = await _seed_input(database, store, tmp_path, suffix)
            first = await _executor(
                database, store, tmp_path, _RecordingSandbox(store)
            ).execute(first_job, asyncio.Event())
            assert first["status"] is JobStatus.SUCCEEDED
            first_versions = list(first["produced_artifact_version_ids"])
            await _settle_prior_import(database, first_job, first_versions)

            analysis_version = None
            async with database.transaction() as repositories:
                for vid in first_versions:
                    row = await repositories.artifacts.get_version(vid)
                    if (row.get("generation_config") or {}).get("format") == (
                        "binary-analysis-result"
                    ):
                        analysis_version = vid
                        config = dict(row["generation_config"])
                        break
            assert analysis_version is not None, "the first run must publish an analysis result"
            config.pop("reuse_key", None)
            async with database.engine.begin() as connection:
                await connection.execute(
                    update(artifact_versions)
                    .where(artifact_versions.c.id == analysis_version)
                    .values(generation_config=config)
                )

            second_suffix = f"reuse-miss-{uuid.uuid4().hex[:12]}"
            async with database.transaction() as repositories:
                first_task = await repositories.tasks.get(first_job["task_id"])
                await repositories.tasks.create(
                    Task(
                        schema_version="1.0.0",
                        id=f"task:{second_suffix}",
                        project_id=first_task["project_id"],
                        artifact_version_ids=list(first_task["artifact_version_ids"]),
                        status=TaskStatus.CREATED,
                        result=None,
                        failure=None,
                        idempotency_key=f"task-{second_suffix}-key",
                        resource_budget=cast(ResourceBudget, budget()),
                        created_at=TIMESTAMP,
                        updated_at=TIMESTAMP,
                    )
                )
            second_job = cast(
                Job,
                {
                    **first_job,
                    "id": f"job:{second_suffix}",
                    "task_id": f"task:{second_suffix}",
                    "idempotency_key": f"job-{second_suffix}-key",
                },
            )
            second_sandbox = _RecordingSandbox(store)
            second = await _executor(database, store, tmp_path, second_sandbox).execute(
                second_job, asyncio.Event()
            )
            assert second["status"] is JobStatus.SUCCEEDED
            assert second_sandbox.requests, "a fingerprint mismatch must re-run the tools"
            assert list(second["produced_artifact_version_ids"]) != first_versions
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_binary_executor_retry_after_lease_loss_registers_fresh_versions(
    persistence_database_url: str, tmp_path: Path
) -> None:
    """A retry attempt gets its own derived identity instead of an ID collision.

    Attempt 1 registered its versions, then died from a lost lease (or any
    post-registration failure). Attempt 2 re-runs the chain; its content can
    legitimately differ (planning degradation), so sharing deterministic IDs
    across attempts made the retry fail with derived_artifact_conflict.
    """

    async def scenario() -> None:
        suffix = uuid.uuid4().hex[:12]
        database = Database(DatabaseSettings(persistence_database_url))
        store = LocalContentAddressedStore(tmp_path / "store")
        try:
            first_job, _ = await _seed_input(database, store, tmp_path, suffix)
            first = await _executor(
                database, store, tmp_path, _RecordingSandbox(store)
            ).execute(first_job, asyncio.Event())
            assert first["status"] is JobStatus.SUCCEEDED
            first_versions = list(first["produced_artifact_version_ids"])

            second_job = cast(Job, {**first_job, "attempt": 2})
            second = await _executor(
                database, store, tmp_path, _RecordingSandbox(store)
            ).execute(second_job, asyncio.Event())
            assert second["status"] is JobStatus.SUCCEEDED, second.get("failure")
            second_versions = list(second["produced_artifact_version_ids"])
            assert second_versions != first_versions
            assert len(second_versions) == len(first_versions)
        finally:
            await database.dispose()

    asyncio.run(scenario())
