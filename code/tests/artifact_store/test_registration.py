from __future__ import annotations

import asyncio
import sys
from io import BytesIO
from pathlib import Path
from typing import cast

import pytest
from vulnweaver_artifact_store import (
    ArtifactRegistrationService,
    ArtifactVersionRequest,
    LocalContentAddressedStore,
)
from vulnweaver_contracts import (
    Artifact,
    ArtifactKind,
    PermissionMode,
    Project,
    ResourceBudget,
    SchemaVersion,
    ToolIdentity,
)
from vulnweaver_persistence import Database, DatabaseSettings, PersistenceInvariantError

from tests.persistence.factories import TIMESTAMP, budget

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


def test_artifact_bytes_and_metadata_are_registered_with_lineage(
    persistence_database_url: str, tmp_path: Path
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        service = ArtifactRegistrationService(
            LocalContentAddressedStore(tmp_path), database
        )
        try:
            async with database.transaction() as repositories:
                await repositories.projects.add(_project())

            source_artifact = _artifact(
                "artifact:t04-source",
                "artifact-version:t04-source",
                ArtifactKind.SOURCE_ARCHIVE,
            )
            source_request = ArtifactVersionRequest(
                id="artifact-version:t04-source",
                artifact_id=source_artifact["id"],
                generation_config={},
                created_at=TIMESTAMP,
            )
            source_result = await service.register_artifact(
                source_artifact,
                source_request,
                BytesIO(b"authorized source archive"),
                max_bytes=1024,
            )
            assert source_result.version_created
            assert source_result.stored_object.created

            repeated = await service.register_version(
                ArtifactVersionRequest(
                    id="artifact-version:t04-repeated",
                    artifact_id=source_artifact["id"],
                    generation_config={"request": "repeat"},
                    created_at=TIMESTAMP,
                ),
                BytesIO(b"authorized source archive"),
                max_bytes=1024,
            )
            assert not repeated.version_created
            assert not repeated.stored_object.created
            assert repeated.version["id"] == source_result.version["id"]

            derived_artifact = _artifact(
                "artifact:t04-derived",
                "artifact-version:t04-derived",
                ArtifactKind.DERIVED,
            )
            tool = ToolIdentity(
                name="safe-transform",
                version="1.0.0",
                image_digest="sha256:" + "b" * 64,
            )
            derived = await service.register_artifact(
                derived_artifact,
                ArtifactVersionRequest(
                    id="artifact-version:t04-derived",
                    artifact_id=derived_artifact["id"],
                    parent_version_id=source_result.version["id"],
                    produced_by=tool,
                    generation_config={"format": "normalized"},
                    created_at=TIMESTAMP,
                ),
                BytesIO(b"normalized harmless output"),
                max_bytes=1024,
            )

            async with database.transaction() as repositories:
                stored_artifact = await repositories.artifacts.get(
                    derived_artifact["id"]
                )
                stored_version = await repositories.artifacts.get_version(
                    derived.version["id"]
                )
            assert stored_artifact["current_version_id"] == derived.version["id"]
            assert stored_version["parent_version_id"] == source_result.version["id"]
            assert stored_version["produced_by"] == tool
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_derived_artifacts_require_parent_and_tool_before_writing(
    persistence_database_url: str, tmp_path: Path
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        store = LocalContentAddressedStore(tmp_path)
        service = ArtifactRegistrationService(store, database)
        artifact = _artifact(
            "artifact:t04-invalid",
            "artifact-version:t04-invalid",
            ArtifactKind.DERIVED,
        )
        try:
            with pytest.raises(PersistenceInvariantError) as captured:
                await service.register_artifact(
                    artifact,
                    ArtifactVersionRequest(
                        id="artifact-version:t04-invalid",
                        artifact_id=artifact["id"],
                        generation_config={},
                        created_at=TIMESTAMP,
                    ),
                    BytesIO(b"must not be written"),
                    max_bytes=1024,
                )
            assert captured.value.details["mismatched_fields"] == [
                "parent_version_id",
                "produced_by",
            ]
            assert list((tmp_path / "objects" / "sha256").rglob("*")) == []
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_string_derived_kind_cannot_bypass_lineage_requirements(
    persistence_database_url: str, tmp_path: Path
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        store = LocalContentAddressedStore(tmp_path)
        service = ArtifactRegistrationService(store, database)
        artifact = _artifact(
            "artifact:t04-string-derived",
            "artifact-version:t04-string-derived",
            cast(ArtifactKind, "derived"),
        )
        try:
            with pytest.raises(PersistenceInvariantError) as captured:
                await service.register_artifact(
                    artifact,
                    ArtifactVersionRequest(
                        id="artifact-version:t04-string-derived",
                        artifact_id=artifact["id"],
                        generation_config={},
                        created_at=TIMESTAMP,
                    ),
                    BytesIO(b"must not be written"),
                    max_bytes=1024,
                )
            assert captured.value.details["mismatched_fields"] == [
                "parent_version_id",
                "produced_by",
            ]
            assert list((tmp_path / "objects" / "sha256").rglob("*")) == []
        finally:
            await database.dispose()

    asyncio.run(scenario())


def _project() -> Project:
    return Project(
        schema_version=SchemaVersion.VALUE_1_0_0,
        id="project:t04",
        name="T04 artifact project",
        input_scope=["local://authorized-sample"],
        permission_mode=PermissionMode.REQUEST_PERMISSION,
        exploit_validation_enabled=False,
        resource_budget=cast(ResourceBudget, budget()),
        created_at=TIMESTAMP,
    )


def _artifact(identifier: str, version_id: str, kind: ArtifactKind) -> Artifact:
    return Artifact(
        schema_version=SchemaVersion.VALUE_1_0_0,
        id=identifier,
        project_id="project:t04",
        kind=kind,
        current_version_id=version_id,
        created_at=TIMESTAMP,
    )
