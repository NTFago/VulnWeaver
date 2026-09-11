"""Regression: audit entry points must see PAIR graphs on derived versions.

PR #72 (418387c) re-attributed binary PAIR functions to the image the
analysis actually read.  For a packed upload that is the derived
``upx-unpacked-binary`` version -- a child of the uploaded version, absent
from ``task.artifact_version_ids`` -- so both audit entry points kept
iterating an empty index and reported a successful no_findings baseline.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any, cast
from uuid import uuid4

from sqlalchemy import insert
from vulnweaver_artifact_store import LocalContentAddressedStore
from vulnweaver_contracts import ArtifactKind, JobKind, JobStatus, PairFunction
from vulnweaver_orchestrator import AuditWorkspace, SemanticAuditor
from vulnweaver_persistence import Database, DatabaseSettings
from vulnweaver_persistence.models import job_results as job_results_table

from tests.persistence.factories import artifact, artifact_version, job, project, task

NOW = datetime(2026, 9, 10, 8, 0, tzinfo=UTC)
ADDRESS = 0x401000


def binary_pair_function(identifier: str, version_id: str) -> PairFunction:
    return PairFunction(
        schema_version="1.0.0",
        id=identifier,
        artifact_version_id=version_id,
        name="handle_note",
        symbol="handle_note",
        language="c",
        source_location=None,
        binary_location={
            "artifact_version_id": version_id,
            "image_base": 0x400000,
            "virtual_address": ADDRESS,
            "file_offset": 0x1000,
            "instruction_end": ADDRESS + 16,
        },
        signature="void handle_note(char *)",
        attributes={"pseudocode": "void handle_note(char *buf) { char tmp[8]; strcpy(tmp, buf); }"},
    )


async def seed_packed_task(database: Database) -> tuple[str, str, str]:
    """Seed the exact lineage PR #72 produces for a packed upload.

    The task only references the uploaded (packed) version; binary analysis
    unpacks it into a derived version and keys the PAIR graphs there, with the
    ``binary-analysis-result`` output pointing at that analyzed version through
    ``parent_version_id``.  Returns (task_id, upload_version_id, unpacked_id).
    """

    suffix = uuid4().hex
    task_id = f"task:{suffix}"
    upload_version_id = f"artifact-version:upload-{suffix}"
    unpacked_version_id = f"artifact-version:unpacked-{suffix}"
    analysis_version_id = f"artifact-version:analysis-{suffix}"
    async with database.transaction() as repositories:
        await repositories.projects.add(project(f"project:{suffix}"))
        upload_artifact = dict(
            artifact(
                f"artifact:{suffix}",
                project_id=f"project:{suffix}",
                current_version_id=upload_version_id,
            )
        )
        upload_artifact["kind"] = "elf"
        await repositories.artifacts.add(cast(Any, upload_artifact))
        await repositories.artifacts.add_version(
            artifact_version(
                upload_version_id, artifact_id=f"artifact:{suffix}", digest_character="a"
            )
        )
        unpacked_artifact = dict(
            artifact(
                f"artifact:unpacked-{suffix}",
                project_id=f"project:{suffix}",
                current_version_id=unpacked_version_id,
            )
        )
        unpacked_artifact["kind"] = "derived"
        await repositories.artifacts.add(cast(Any, unpacked_artifact))
        unpacked_version = artifact_version(
            unpacked_version_id, artifact_id=f"artifact:unpacked-{suffix}", digest_character="b"
        )
        unpacked_version["parent_version_id"] = upload_version_id
        unpacked_version["generation_config"] = {"format": "upx-unpacked-binary", "tool": "upx"}
        await repositories.artifacts.add_version(unpacked_version)
        analysis_artifact = dict(
            artifact(
                f"artifact:analysis-{suffix}",
                project_id=f"project:{suffix}",
                current_version_id=analysis_version_id,
            )
        )
        analysis_artifact["kind"] = "derived"
        await repositories.artifacts.add(cast(Any, analysis_artifact))
        analysis_version = artifact_version(
            analysis_version_id, artifact_id=f"artifact:analysis-{suffix}", digest_character="c"
        )
        analysis_version["parent_version_id"] = unpacked_version_id
        analysis_version["generation_config"] = {
            "format": "binary-analysis-result",
            "source_artifact_version_id": upload_version_id,
            "analyzed_artifact_version_id": unpacked_version_id,
        }
        await repositories.artifacts.add_version(analysis_version)
        await repositories.tasks.create(
            task(
                task_id,
                project_id=f"project:{suffix}",
                artifact_version_ids=[upload_version_id],
                idempotency_key=f"task:{suffix}",
            )
        )
        import_job = job(
            f"job:binary-import:{suffix}",
            task_id=task_id,
            idempotency_key=f"job:binary-import:{suffix}",
            kind=JobKind.IMPORT,
        )
        import_job["status"] = JobStatus.SUCCEEDED
        import_job["tool"] = {"name": "binary-import", "version": "1.0.0", "image_digest": None}
        await repositories.jobs.create_without_outbox(import_job)
        await repositories.pair.import_graph(
            [binary_pair_function(f"pair-fn:{suffix}", unpacked_version_id)],
            [],
            [],
            None,
            created_at=NOW,
        )
    async with database.engine.begin() as connection:
        await connection.execute(
            insert(job_results_table).values(
                job_id=import_job["id"],
                schema_version="1.0.0",
                status="succeeded",
                produced_artifact_version_ids=[unpacked_version_id, analysis_version_id],
                evidence_ids=[],
                failure=None,
                result_fingerprint="a" * 64,
                completed_at=NOW,
            )
        )
    return task_id, upload_version_id, unpacked_version_id


def test_auditable_functions_cover_derived_analysis_version(
    persistence_database_url: str, tmp_path: object
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        task_id, upload_version_id, unpacked_version_id = await seed_packed_task(database)
        auditor = SemanticAuditor(
            database, cast(Any, None), LocalContentAddressedStore(cast(Any, tmp_path))
        )
        try:
            entries, source_version_id, binary_version_id = await auditor._auditable_functions(
                task_id
            )
        finally:
            await database.dispose()
        assert [version_id for version_id, _ in entries] == [unpacked_version_id]
        assert entries[0][1]["name"] == "handle_note"
        # The binary anchor must be the version that actually holds the PAIR
        # graph, not the uploaded image the task references.
        assert binary_version_id == unpacked_version_id
        assert binary_version_id != upload_version_id
        assert source_version_id == ""

    asyncio.run(scenario())


def test_audit_workspace_loads_derived_version_functions(
    persistence_database_url: str, tmp_path: object
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        task_id, upload_version_id, unpacked_version_id = await seed_packed_task(database)
        workspace = AuditWorkspace(
            database, LocalContentAddressedStore(cast(Any, tmp_path)), task_id
        )
        try:
            await workspace.load()
        finally:
            await database.dispose()
        assert upload_version_id in workspace.version_ids()
        assert unpacked_version_id in workspace.version_ids()
        assert workspace.version_kind(unpacked_version_id) is ArtifactKind.DERIVED
        assert workspace.function_count == 1
        ref = workspace.function_refs()[0]
        assert ref.version_id == unpacked_version_id
        assert ref.function["name"] == "handle_note"

    asyncio.run(scenario())
