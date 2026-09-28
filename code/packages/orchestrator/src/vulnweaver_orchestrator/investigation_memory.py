"""Project-scoped investigation memory: the agent's own conclusions, persisted.

The audit agent currently starts every task from zero: whatever a previous
investigation on the same project substantiated, refuted or failed to anchor is
invisible to the next one.  This module gives the agent a durable, project-level
memory of *its own judgments* -- anchored findings, candidates that failed
anchoring, and how far the investigation actually got -- stored as versions of
one derived artifact so the memory timeline is the artifact's version chain.

The memory deliberately records conclusions, not tool dumps: the same scanner
lead re-firing on a new task should arrive pre-judged ("dismissed last time and
why"), which is what lets a long-running agent accumulate expertise instead of
repeating yesterday's work.
"""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import logging
from collections.abc import Mapping, Sequence
from typing import Protocol, cast

from vulnweaver_artifact_store import ArtifactStore, ArtifactStoreError
from vulnweaver_contracts import (
    Artifact,
    ArtifactKind,
    ArtifactVersion,
    JsonObject,
    JsonValue,
    SchemaVersion,
    ToolIdentity,
    validate_contract,
)
from vulnweaver_persistence import Database, EntityConflict, EntityNotFound

LOGGER = logging.getLogger("vulnweaver.investigation_memory")

MEMORY_FORMAT = "investigation-memory"
MEMORY_SCHEMA_VERSION = "1.0.0"
_MAX_MEMORY_FINDINGS = 64
_MAX_MEMORY_DROPPED = 32
_MAX_MEMORY_INVESTIGATION_STEPS = 24
_DEFAULT_LOADED_INVESTIGATIONS = 3
_MAX_MEMORY_BYTES = 4 * 1024 * 1024


def memory_artifact_id(project_id: str) -> str:
    digest = hashlib.sha256(project_id.encode()).hexdigest()[:32]
    return f"artifact:investigation-memory:{digest}"


def build_memory_document(
    *,
    task_id: str,
    project_id: str,
    run_id: str,
    created_at: str,
    findings: Sequence[Mapping[str, object]],
    dropped_candidates: Sequence[Mapping[str, object]],
    investigation: Sequence[Mapping[str, object]],
    completed: bool,
    source_version_id: str = "",
    binary_version_id: str = "",
) -> JsonObject:
    """One audit's durable conclusions, bounded to a fixed-cost record."""

    def bounded(items: Sequence[Mapping[str, object]], limit: int) -> list[JsonObject]:
        return [cast(JsonObject, dict(item)) for item in items[:limit]]

    document = cast(JsonObject, {
        "schema_version": MEMORY_SCHEMA_VERSION,
        "format": MEMORY_FORMAT,
        "task_id": task_id,
        "project_id": project_id,
        "run_id": run_id,
        "created_at": created_at,
        "completed": completed,
        "findings": bounded(findings, _MAX_MEMORY_FINDINGS),
        "dropped_candidates": bounded(dropped_candidates, _MAX_MEMORY_DROPPED),
        "investigation": bounded(investigation, _MAX_MEMORY_INVESTIGATION_STEPS),
        "source_version_id": source_version_id,
        "binary_version_id": binary_version_id,
    })
    return document


class InvestigationMemory(Protocol):
    """Write one audit's conclusions; read the project's recent ones."""

    async def write(
        self,
        *,
        project_id: str,
        parent_version_id: str,
        document: Mapping[str, object],
        produced_by: ToolIdentity,
    ) -> str | None: ...

    async def latest(
        self, project_id: str, *, limit: int = _DEFAULT_LOADED_INVESTIGATIONS
    ) -> list[JsonObject]: ...


class DatabaseInvestigationMemory:
    """Memory as versions of one derived artifact per project."""

    def __init__(self, database: Database, store: ArtifactStore) -> None:
        self._database = database
        self._store = store

    async def write(
        self,
        *,
        project_id: str,
        parent_version_id: str,
        document: Mapping[str, object],
        produced_by: ToolIdentity,
    ) -> str | None:
        content = json.dumps(
            document, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        run_id = str(document.get("run_id") or "unknown")
        created_at = str(document.get("created_at") or "")
        version_id = (
            "artifact-version:investigation-memory:"
            + hashlib.sha256(run_id.encode()).hexdigest()[:32]
        )
        artifact_id = memory_artifact_id(project_id)
        try:
            # The CAS write is idempotent and lives outside the transaction; a
            # failed registration at worst leaves an unreferenced object.
            stored = await asyncio.to_thread(
                self._store.put_stream, io.BytesIO(content), max_bytes=_MAX_MEMORY_BYTES
            )
            async with self._database.transaction() as repositories:
                try:
                    await repositories.artifacts.get(artifact_id)
                except EntityNotFound:
                    artifact = Artifact(
                        schema_version=SchemaVersion.VALUE_1_0_0,
                        id=artifact_id,
                        project_id=project_id,
                        kind=ArtifactKind.DERIVED,
                        current_version_id=version_id,
                        created_at=created_at,
                    )
                    validate_contract("Artifact", artifact)
                    await repositories.artifacts.add(artifact)
                version = ArtifactVersion(
                    schema_version=SchemaVersion.VALUE_1_0_0,
                    id=version_id,
                    artifact_id=artifact_id,
                    digest=stored.digest,
                    object_ref=stored.object_ref,
                    parent_version_id=parent_version_id or None,
                    produced_by=produced_by,
                    generation_config={"format": MEMORY_FORMAT, "run_id": run_id},
                    created_at=created_at,
                )
                validate_contract("ArtifactVersion", version)
                await repositories.artifacts.add_version(version)
            return version_id
        except (EntityConflict, ArtifactStoreError, ValueError) as error:
            # Memory is an accelerator, never a precondition: a failed write
            # must not fail the audit that produced it.
            LOGGER.warning(
                "investigation_memory_write_failed project=%s: %s",
                project_id,
                str(error)[:400],
            )
            return None

    async def latest(
        self, project_id: str, *, limit: int = _DEFAULT_LOADED_INVESTIGATIONS
    ) -> list[JsonObject]:
        artifact_id = memory_artifact_id(project_id)
        try:
            async with self._database.transaction() as repositories:
                await repositories.artifacts.get(artifact_id)
                versions = await repositories.artifacts.list_versions(artifact_id)
        except EntityNotFound:
            return []
        documents: list[JsonObject] = []
        ordered = sorted(versions, key=lambda item: str(item["created_at"]), reverse=True)
        for version in ordered[: max(1, limit)]:
            object_ref = str(version["object_ref"])
            document = await asyncio.to_thread(_read_document, self._store, object_ref)
            if document is not None:
                documents.append(document)
        return documents


def _read_document(store: ArtifactStore, object_ref: str) -> JsonObject | None:
    """Read one memory document; unreadable entries are skipped, not fatal."""

    try:
        with store.open(object_ref) as stream:
            loaded = json.load(stream)
    except (ArtifactStoreError, OSError, ValueError):
        return None
    if not isinstance(loaded, Mapping):
        return None
    narrowed = cast(Mapping[str, object], loaded)
    return cast(JsonObject, dict(narrowed))


def memory_context_entry(document: Mapping[str, object]) -> JsonObject:
    """The bounded slice of one memory document the audit agent sees."""

    def bounded(key: str, limit: int) -> JsonValue:
        value = document.get(key)
        if isinstance(value, list):
            return cast(JsonValue, value[:limit])
        return cast(JsonValue, [])

    return {
        "task_id": str(document.get("task_id") or ""),
        "created_at": str(document.get("created_at") or ""),
        "completed": document.get("completed") is True,
        "findings": bounded("findings", _MAX_MEMORY_FINDINGS),
        "dropped_candidates": bounded("dropped_candidates", _MAX_MEMORY_DROPPED),
        "investigation": bounded("investigation", 12),
    }


__all__ = [
    "DatabaseInvestigationMemory",
    "InvestigationMemory",
    "MEMORY_FORMAT",
    "build_memory_document",
    "memory_artifact_id",
    "memory_context_entry",
]

