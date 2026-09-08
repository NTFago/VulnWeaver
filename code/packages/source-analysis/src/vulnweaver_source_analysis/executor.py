"""Safe source-import execution for the shared Worker SDK."""

from __future__ import annotations

import asyncio
import io
import json
import shutil
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import cast

from vulnweaver_artifact_store import LocalContentAddressedStore
from vulnweaver_contracts import (
    Artifact,
    ArtifactKind,
    ArtifactVersion,
    FailureKind,
    Job,
    JobKind,
    JobStatus,
    JsonObject,
    SchemaVersion,
    SourceImportResult,
    StructuredFailure,
    ToolIdentity,
    WorkerResult,
    validate_contract,
)
from vulnweaver_persistence import Database, EntityConflict, EntityNotFound

from vulnweaver_source_analysis.archive import (
    SafeArchiveImporter,
    SourceImportError,
)
from vulnweaver_source_analysis.indexer import SourceIndexer


class SourceImportExecutionError(RuntimeError):
    """A source import failed before a terminal WorkerResult could be produced."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        kind: FailureKind = FailureKind.VALIDATION,
        retryable: bool = False,
        details: Mapping[str, object] | None = None,
    ) -> None:
        self.code = code
        self.kind = kind
        self.retryable = retryable
        self.details = dict(details or {})
        super().__init__(message)


class SourceImportExecutor:
    """Index one registered archive and publish the immutable derived index artifact."""

    def __init__(
        self,
        database: Database,
        store: LocalContentAddressedStore,
        *,
        importer: SafeArchiveImporter | None = None,
        indexer: SourceIndexer | None = None,
        scratch_root: str | Path | None = None,
    ) -> None:
        self._database = database
        self._store = store
        self._importer = importer or SafeArchiveImporter()
        self._indexer = indexer or SourceIndexer()
        self._scratch_root = Path(scratch_root) if scratch_root is not None else None

    async def execute(self, job: Job, cancellation: asyncio.Event) -> WorkerResult:
        try:
            return await self._execute(job, cancellation)
        except SourceImportError as error:
            return _failed_result(
                job["id"],
                code=f"source_import.{error.code}",
                kind=FailureKind.VALIDATION,
                message=error.message,
                retryable=False,
                details=error.details,
            )
        except SourceImportExecutionError as error:
            return _failed_result(
                job["id"],
                code=error.code,
                kind=error.kind,
                message=str(error),
                retryable=error.retryable,
                details=error.details,
            )
        except (OSError, TimeoutError) as error:
            return _failed_result(
                job["id"],
                code="source_import.environment_error",
                kind=FailureKind.ENVIRONMENT,
                message="source import storage or scratch environment failed",
                retryable=True,
                details={"exception_type": type(error).__name__},
            )
        except ValueError as error:
            return _failed_result(
                job["id"],
                code="source_import.index_validation_failed",
                kind=FailureKind.VALIDATION,
                message=str(error),
                retryable=False,
            )

    async def _execute(self, job: Job, cancellation: asyncio.Event) -> WorkerResult:
        if job["kind"] != JobKind.IMPORT:
            raise SourceImportExecutionError(
                "source_import.invalid_job_kind",
                "source executor received a non-import job",
            )
        parent_version_id = _required_argument(job, "artifact_version_id")
        if len(job["input_refs"]) != 1:
            raise SourceImportExecutionError(
                "source_import.invalid_input_count",
                "source import requires exactly one input object",
            )
        object_ref = job["input_refs"][0]
        if cancellation.is_set():
            return _cancelled_result(job["id"])

        scratch = Path(tempfile.mkdtemp(prefix="vulnweaver-source-", dir=self._scratch_root))
        try:
            extracted = scratch / "tree"
            summary = await asyncio.to_thread(
                self._extract_archive,
                object_ref,
                extracted,
            )
            if cancellation.is_set():
                return _cancelled_result(job["id"])
            result = await asyncio.to_thread(
                self._indexer.index,
                extracted,
                parent_version_id,
                created_at=job["created_at"],
            )
            if cancellation.is_set():
                return _cancelled_result(job["id"])
            derived_version_id = _derived_identifier("artifact-version", job["id"])
            derived_artifact_id = _derived_identifier("artifact", job["id"])
            await self._publish_index(
                job,
                result,
                parent_version_id,
                derived_artifact_id,
                derived_version_id,
                summary.files,
            )
            return WorkerResult(
                schema_version=SchemaVersion.VALUE_1_0_0,
                job_id=job["id"],
                status=JobStatus.SUCCEEDED,
                produced_artifact_version_ids=[derived_version_id],
                evidence_ids=[],
                failure=None,
            )
        finally:
            shutil.rmtree(scratch, ignore_errors=True)

    def _extract_archive(self, object_ref: str, extracted: Path):
        with self._store.open(object_ref) as archive_stream:
            return self._importer.extract(archive_stream, extracted)

    async def _publish_index(
        self,
        job: Job,
        result: SourceImportResult,
        parent_version_id: str,
        artifact_id: str,
        version_id: str,
        file_count: int,
    ) -> str:
        encoded = json.dumps(
            result, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        # ADR-012 intentionally publishes deterministic bytes before metadata. A
        # failed transaction may leave one safe unreferenced CAS object for later
        # controlled GC; deleting it here could race with another publisher that
        # already reused the same digest.
        stored = await _put_bytes(self._store, encoded)
        try:
            async with self._database.transaction() as repositories:
                parent = await repositories.artifacts.get_version(parent_version_id)
                source_artifact = await repositories.artifacts.get(parent["artifact_id"])
                artifact = Artifact(
                    schema_version=SchemaVersion.VALUE_1_0_0,
                    id=artifact_id,
                    project_id=source_artifact["project_id"],
                    kind=ArtifactKind.DERIVED,
                    current_version_id=version_id,
                    created_at=job["created_at"],
                )
                version = ArtifactVersion(
                    schema_version=SchemaVersion.VALUE_1_0_0,
                    id=version_id,
                    artifact_id=artifact_id,
                    digest=stored.digest,
                    object_ref=stored.object_ref,
                    parent_version_id=parent_version_id,
                    produced_by=_tool_identity(job),
                    generation_config={
                        "format": "source-import-result",
                        "files": file_count,
                        "schema_version": str(result["schema_version"]),
                    },
                    created_at=job["created_at"],
                )
                validate_contract("Artifact", artifact)
                validate_contract("ArtifactVersion", version)
                await repositories.artifacts.add(artifact)
                await repositories.artifacts.add_version(version)
        except EntityNotFound as error:
            raise SourceImportExecutionError(
                "source_import.parent_artifact_missing",
                "source import parent artifact disappeared",
                kind=FailureKind.INTERNAL,
            ) from error
        except EntityConflict as error:
            # The failed INSERT aborts its transaction. Verify a concurrent or
            # replayed deterministic result in a fresh transaction.
            async with self._database.transaction() as repositories:
                existing = await repositories.artifacts.get_version(version_id)
                if (
                    existing["artifact_id"] != artifact_id
                    or existing["digest"] != stored.digest
                    or existing.get("parent_version_id") != parent_version_id
                    or existing.get("produced_by") != _tool_identity(job)
                ):
                    raise SourceImportExecutionError(
                        "source_import.derived_artifact_conflict",
                        "deterministic derived artifact conflicts with existing metadata",
                        kind=FailureKind.INTERNAL,
                    ) from error
        return stored.object_ref


async def _put_bytes(store: LocalContentAddressedStore, value: bytes):
    return await asyncio.to_thread(store.put_stream, io.BytesIO(value), max_bytes=len(value))


def _tool_identity(job: Job) -> ToolIdentity:
    value = job.get("tool")
    if not isinstance(value, Mapping):
        return ToolIdentity(name="source-import", version="1.0.0", image_digest=None)
    name = value.get("name")
    version = value.get("version")
    digest = value.get("image_digest")
    return ToolIdentity(
        name=name if name else "source-import",
        version=version if version else "1.0.0",
        image_digest=digest if isinstance(digest, str) else None,
    )


def _required_argument(job: Job, name: str) -> str:
    arguments = job.get("arguments")
    value = arguments.get(name) if isinstance(arguments, Mapping) else None
    if not isinstance(value, str) or not value:
        raise SourceImportExecutionError(
            "source_import.invalid_arguments",
            f"source import argument {name!r} is required",
            details={"argument": name},
        )
    return value


def _derived_identifier(prefix: str, job_id: str) -> str:
    import hashlib

    return f"{prefix}:{hashlib.sha256(job_id.encode('utf-8')).hexdigest()[:32]}"


def _cancelled_result(job_id: str) -> WorkerResult:
    return WorkerResult(
        schema_version=SchemaVersion.VALUE_1_0_0,
        job_id=job_id,
        status=JobStatus.CANCELLED,
        produced_artifact_version_ids=[],
        evidence_ids=[],
        failure=None,
    )


def _failed_result(
    job_id: str,
    *,
    code: str,
    kind: FailureKind,
    message: str,
    retryable: bool,
    details: Mapping[str, object] | None = None,
) -> WorkerResult:
    return WorkerResult(
        schema_version=SchemaVersion.VALUE_1_0_0,
        job_id=job_id,
        status=JobStatus.FAILED,
        produced_artifact_version_ids=[],
        evidence_ids=[],
        failure=StructuredFailure(
            code=code,
            kind=kind,
            message=message,
            retryable=retryable,
            details=cast(JsonObject, dict(details or {})),
        ),
    )
