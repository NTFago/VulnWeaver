"""Coordinate immutable object writes with PostgreSQL metadata registration."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import BinaryIO

from vulnweaver_contracts import (
    Artifact,
    ArtifactKind,
    ArtifactVersion,
    JsonObject,
    SchemaVersion,
    ToolIdentity,
    validate_contract,
)
from vulnweaver_persistence import Database, PersistenceInvariantError

from vulnweaver_artifact_store.store import ArtifactStore, StoredObject


@dataclass(frozen=True, slots=True)
class ArtifactVersionRequest:
    id: str
    artifact_id: str
    generation_config: JsonObject
    created_at: str
    parent_version_id: str | None = None
    produced_by: ToolIdentity | None = None


@dataclass(frozen=True, slots=True)
class ArtifactRegistrationResult:
    artifact: Artifact
    version: ArtifactVersion
    stored_object: StoredObject
    version_created: bool


class ArtifactRegistrationService:
    def __init__(self, store: ArtifactStore, database: Database) -> None:
        self._store = store
        self._database = database

    async def register_artifact(
        self,
        artifact: Artifact,
        version_request: ArtifactVersionRequest,
        source: BinaryIO,
        *,
        max_bytes: int,
    ) -> ArtifactRegistrationResult:
        validate_contract("Artifact", artifact)
        self._ensure_request_matches_artifact(artifact, version_request, initial=True)
        stored_object = await asyncio.to_thread(
            self._store.put_stream, source, max_bytes=max_bytes
        )
        version = _build_version(version_request, stored_object)
        async with self._database.transaction() as repositories:
            await repositories.artifacts.add(artifact)
            result = await repositories.artifacts.add_version(version)
        return ArtifactRegistrationResult(
            artifact=artifact,
            version=result.value,
            stored_object=stored_object,
            version_created=result.created,
        )

    async def register_version(
        self,
        version_request: ArtifactVersionRequest,
        source: BinaryIO,
        *,
        max_bytes: int,
    ) -> ArtifactRegistrationResult:
        async with self._database.transaction() as repositories:
            artifact = await repositories.artifacts.get(version_request.artifact_id)
        self._ensure_request_matches_artifact(artifact, version_request, initial=False)
        stored_object = await asyncio.to_thread(
            self._store.put_stream, source, max_bytes=max_bytes
        )
        version = _build_version(version_request, stored_object)
        async with self._database.transaction() as repositories:
            result = await repositories.artifacts.add_version(version)
        return ArtifactRegistrationResult(
            artifact=artifact,
            version=result.value,
            stored_object=stored_object,
            version_created=result.created,
        )

    @staticmethod
    def _ensure_request_matches_artifact(
        artifact: Artifact,
        request: ArtifactVersionRequest,
        *,
        initial: bool,
    ) -> None:
        mismatches: list[str] = []
        if request.artifact_id != artifact["id"]:
            mismatches.append("artifact_id")
        if initial and artifact["current_version_id"] != request.id:
            mismatches.append("current_version_id")
        if artifact["kind"] == ArtifactKind.DERIVED:
            if request.parent_version_id is None:
                mismatches.append("parent_version_id")
            if request.produced_by is None:
                mismatches.append("produced_by")
        if mismatches:
            raise PersistenceInvariantError(
                "artifact version request does not satisfy artifact invariants",
                details={"mismatched_fields": mismatches},
            )


def _build_version(
    request: ArtifactVersionRequest, stored_object: StoredObject
) -> ArtifactVersion:
    version = ArtifactVersion(
        schema_version=SchemaVersion.VALUE_1_0_0,
        id=request.id,
        artifact_id=request.artifact_id,
        digest=stored_object.digest,
        object_ref=stored_object.object_ref,
        generation_config=request.generation_config,
        created_at=request.created_at,
    )
    if request.parent_version_id is not None:
        version["parent_version_id"] = request.parent_version_id
    if request.produced_by is not None:
        version["produced_by"] = request.produced_by
    validate_contract("ArtifactVersion", version)
    return version
