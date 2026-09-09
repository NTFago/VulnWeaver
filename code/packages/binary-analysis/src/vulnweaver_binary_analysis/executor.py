"""Binary import executor for the shared reliable Worker SDK."""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import shutil
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import cast

from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from vulnweaver_artifact_store import ArtifactStoreError, LocalContentAddressedStore, StoredObject
from vulnweaver_contracts import (
    Artifact,
    ArtifactKind,
    ArtifactVersion,
    BinaryAnalysisResult,
    BinaryAnalysisStatus,
    BinaryToolRun,
    FailureKind,
    Job,
    JobKind,
    JobStatus,
    JsonObject,
    SchemaVersion,
    StaticToolStatus,
    StructuredFailure,
    ToolIdentity,
    WorkerResult,
    validate_contract,
)
from vulnweaver_persistence import Database, EntityConflict, EntityNotFound, PersistenceError

from vulnweaver_binary_analysis.headers import (
    BinaryInspectionError,
    extract_strings,
    inspect_binary,
)
from vulnweaver_binary_analysis.tools import (
    AngrAdapter,
    BinaryToolAdapter,
    DetectItEasyAdapter,
    GhidraHeadlessAdapter,
    ObjdumpAdapter,
    ToolCancelled,
    UpxAdapter,
    UpxUnpacker,
)
from vulnweaver_binary_analysis.types import (
    BinaryAnalysisAggregate,
    BinaryAnalysisLimits,
)


class BinaryAnalysisExecutionError(RuntimeError):
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


class BinaryImportExecutor:
    """Inspect one registered ELF/PE and publish immutable normalized analysis."""

    def __init__(
        self,
        database: Database,
        store: LocalContentAddressedStore,
        *,
        limits: BinaryAnalysisLimits | None = None,
        adapters: Sequence[BinaryToolAdapter] | None = None,
        upx: UpxUnpacker | None = None,
        scratch_root: str | Path | None = None,
    ) -> None:
        self._database = database
        self._store = store
        self._limits = limits or BinaryAnalysisLimits()
        self._adapters = tuple(adapters) if adapters is not None else (ObjdumpAdapter(),)
        self._upx = upx or UpxAdapter()
        self._scratch_root = Path(scratch_root) if scratch_root is not None else None

    @classmethod
    def configured(
        cls,
        database: Database,
        store: LocalContentAddressedStore,
        *,
        scratch_root: str | Path | None = None,
        die_executable: str = "diec",
        objdump_executable: str = "objdump",
        ghidra_executable: str | None = None,
        ghidra_script_directory: str | Path | None = None,
        angr_enabled: bool = False,
        upx_executable: str = "upx",
    ) -> BinaryImportExecutor:
        return cls(
            database,
            store,
            adapters=(
                DetectItEasyAdapter(die_executable),
                ObjdumpAdapter(objdump_executable),
                GhidraHeadlessAdapter(ghidra_executable, ghidra_script_directory),
                AngrAdapter(angr_enabled),
            ),
            upx=UpxAdapter(upx_executable),
            scratch_root=scratch_root,
        )

    async def execute(self, job: Job, cancellation: asyncio.Event) -> WorkerResult:
        try:
            return await self._execute(job, cancellation)
        except BinaryInspectionError as error:
            return _failed_result(
                job["id"],
                code=f"binary_import.{error.code}",
                kind=FailureKind.VALIDATION,
                message=error.message,
                retryable=False,
                details=error.details,
            )
        except BinaryAnalysisExecutionError as error:
            return _failed_result(
                job["id"],
                code=error.code,
                kind=error.kind,
                message=str(error),
                retryable=error.retryable,
                details=error.details,
            )
        except ToolCancelled:
            return _cancelled_result(job["id"])
        except ArtifactStoreError as error:
            return _failed_result(
                job["id"],
                code=f"binary_import.{error.code}",
                kind=FailureKind.ENVIRONMENT,
                message=error.message,
                retryable=error.retryable,
                details=error.details,
            )
        except IntegrityError as error:
            return _failed_result(
                job["id"],
                code="binary_import.persistence_integrity_failed",
                kind=FailureKind.INTERNAL,
                message="binary analysis persistence integrity check failed",
                retryable=False,
                details={"exception_type": type(error).__name__},
            )
        except PersistenceError as error:
            return _failed_result(
                job["id"],
                code=f"binary_import.{error.code}",
                kind=FailureKind.INTERNAL,
                message=error.message,
                retryable=error.retryable,
                details=error.details,
            )
        except SQLAlchemyError as error:
            return _failed_result(
                job["id"],
                code="binary_import.persistence_unavailable",
                kind=FailureKind.ENVIRONMENT,
                message="binary analysis persistence operation failed",
                retryable=True,
                details={"exception_type": type(error).__name__},
            )
        except (OSError, TimeoutError) as error:
            return _failed_result(
                job["id"],
                code="binary_import.environment_error",
                kind=FailureKind.ENVIRONMENT,
                message="binary analysis scratch or tool environment failed",
                retryable=True,
                details={"exception_type": type(error).__name__},
            )
        except (TypeError, ValueError) as error:
            return _failed_result(
                job["id"],
                code="binary_import.result_validation_failed",
                kind=FailureKind.INTERNAL,
                message=str(error),
                retryable=False,
            )

    async def _execute(self, job: Job, cancellation: asyncio.Event) -> WorkerResult:
        if job["kind"] != JobKind.IMPORT:
            raise BinaryAnalysisExecutionError(
                "binary_import.invalid_job_kind", "binary executor received a non-import job"
            )
        if _tool_name(job) != "binary-import":
            raise BinaryAnalysisExecutionError(
                "binary_import.invalid_tool", "binary executor requires the binary-import tool"
            )
        parent_version_id = _required_argument(job, "artifact_version_id")
        object_ref = _single_input(job)
        await self._validate_input(job, parent_version_id, object_ref)
        if cancellation.is_set():
            return _cancelled_result(job["id"])

        scratch = Path(tempfile.mkdtemp(prefix="vulnweaver-binary-", dir=self._scratch_root))
        try:
            input_path = scratch / "input.bin"
            await asyncio.to_thread(self._copy_input, object_ref, input_path)
            original_metadata = await asyncio.to_thread(inspect_binary, input_path, self._limits)
            aggregate = BinaryAnalysisAggregate(original_metadata)
            aggregate.tool_runs.append(_header_run())

            unpacked_path = scratch / "unpacked.bin"
            upx_outcome = await self._upx.unpack(
                input_path, unpacked_path, self._limits, cancellation
            )
            aggregate.tool_runs.append(upx_outcome.run)
            analyzed_path = input_path
            analyzed_version_id = parent_version_id
            produced: list[str] = []
            metadata = original_metadata
            if upx_outcome.unpacked_path is not None:
                metadata = await asyncio.to_thread(
                    inspect_binary, upx_outcome.unpacked_path, self._limits
                )
                unpacked_version_id = _derived_identifier(
                    "artifact-version", job["id"], "upx-unpacked"
                )
                unpacked_artifact_id = _derived_identifier("artifact", job["id"], "upx-unpacked")
                stored_unpacked = await asyncio.to_thread(
                    _put_path, self._store, upx_outcome.unpacked_path, self._limits.max_input_bytes
                )
                await self._register_derived(
                    job,
                    parent_version_id=parent_version_id,
                    artifact_id=unpacked_artifact_id,
                    version_id=unpacked_version_id,
                    stored=stored_unpacked,
                    generation_config={"format": "upx-unpacked-binary", "tool": "upx"},
                )
                analyzed_path = upx_outcome.unpacked_path
                analyzed_version_id = unpacked_version_id
                produced.append(unpacked_version_id)
                aggregate = BinaryAnalysisAggregate(metadata)
                aggregate.packed = True
                aggregate.packer = "UPX"
                aggregate.tool_runs.extend((_header_run(), upx_outcome.run))
            elif original_metadata.packed:
                aggregate.packed = True

            aggregate.strings = list(
                await asyncio.to_thread(extract_strings, analyzed_path, metadata, self._limits)
            )
            for adapter in self._adapters:
                if cancellation.is_set():
                    return _cancelled_result(job["id"], produced)
                contribution = await adapter.analyze(
                    analyzed_path, metadata, self._limits, cancellation
                )
                aggregate.merge(contribution, self._limits)

            result = _build_result(
                parent_version_id,
                analyzed_version_id,
                aggregate,
                created_at=job["created_at"],
            )
            validate_contract("BinaryAnalysisResult", result)
            result_bytes = json.dumps(
                result, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")
            stored_result = await asyncio.to_thread(
                self._store.put_stream, io.BytesIO(result_bytes), max_bytes=len(result_bytes)
            )
            result_version_id = _derived_identifier("artifact-version", job["id"], "analysis")
            result_artifact_id = _derived_identifier("artifact", job["id"], "analysis")
            await self._register_derived(
                job,
                parent_version_id=analyzed_version_id,
                artifact_id=result_artifact_id,
                version_id=result_version_id,
                stored=stored_result,
                generation_config={
                    "format": "binary-analysis-result",
                    "source_artifact_version_id": parent_version_id,
                    "analyzed_artifact_version_id": analyzed_version_id,
                },
            )
            produced.append(result_version_id)
            return WorkerResult(
                schema_version=SchemaVersion.VALUE_1_0_0,
                job_id=job["id"],
                status=JobStatus.SUCCEEDED,
                produced_artifact_version_ids=produced,
                evidence_ids=[],
                failure=None,
            )
        finally:
            await asyncio.to_thread(shutil.rmtree, scratch, True)

    async def _validate_input(self, job: Job, version_id: str, object_ref: str) -> None:
        try:
            async with self._database.transaction() as repositories:
                task = await repositories.tasks.get(job["task_id"])
                version = await repositories.artifacts.get_version(version_id)
                artifact = await repositories.artifacts.get(version["artifact_id"])
        except EntityNotFound as error:
            raise BinaryAnalysisExecutionError(
                "binary_import.input_missing",
                "binary input metadata does not exist",
                kind=FailureKind.VALIDATION,
            ) from error
        if version_id not in task["artifact_version_ids"]:
            raise BinaryAnalysisExecutionError(
                "binary_import.input_not_authorized",
                "binary artifact is not part of the task input scope",
            )
        if artifact["project_id"] != task["project_id"]:
            raise BinaryAnalysisExecutionError(
                "binary_import.project_mismatch", "binary artifact belongs to another project"
            )
        if artifact["kind"] not in {ArtifactKind.ELF, ArtifactKind.PE}:
            raise BinaryAnalysisExecutionError(
                "binary_import.invalid_artifact_kind",
                "binary import requires an ELF or PE artifact",
            )
        if version["object_ref"] != object_ref:
            raise BinaryAnalysisExecutionError(
                "binary_import.object_ref_mismatch",
                "job input reference does not match the registered artifact version",
            )

    def _copy_input(self, object_ref: str, destination: Path) -> None:
        verified = self._store.verify(object_ref)
        if verified.size_bytes > self._limits.max_input_bytes:
            raise BinaryInspectionError(
                "too_large",
                "binary input exceeds the configured size limit",
                details={
                    "size_bytes": verified.size_bytes,
                    "max_bytes": self._limits.max_input_bytes,
                },
            )
        with self._store.open(object_ref) as source, destination.open("xb") as target:
            shutil.copyfileobj(source, target, length=1024 * 1024)

    async def _register_derived(
        self,
        job: Job,
        *,
        parent_version_id: str,
        artifact_id: str,
        version_id: str,
        stored: StoredObject,
        generation_config: JsonObject,
    ) -> ArtifactVersion:
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
                    generation_config=generation_config,
                    created_at=job["created_at"],
                )
                validate_contract("Artifact", artifact)
                validate_contract("ArtifactVersion", version)
                await repositories.artifacts.add(artifact)
                await repositories.artifacts.add_version(version)
                return version
        except EntityConflict as error:
            async with self._database.transaction() as repositories:
                existing = await repositories.artifacts.get_version(version_id)
            if (
                existing["artifact_id"] != artifact_id
                or existing["digest"] != stored.digest
                or existing.get("parent_version_id") != parent_version_id
            ):
                raise BinaryAnalysisExecutionError(
                    "binary_import.derived_artifact_conflict",
                    "deterministic binary artifact conflicts with existing metadata",
                    kind=FailureKind.INTERNAL,
                ) from error
            return existing


def _build_result(
    parent_version_id: str,
    analyzed_version_id: str,
    aggregate: BinaryAnalysisAggregate,
    *,
    created_at: str,
) -> BinaryAnalysisResult:
    required_tool_failed = any(
        run["status"] is StaticToolStatus.FAILED for run in aggregate.tool_runs
    )
    status = (
        BinaryAnalysisStatus.PARTIAL
        if required_tool_failed
        or (aggregate.packed and analyzed_version_id == parent_version_id)
        or not aggregate.functions
        or not aggregate.instructions
        else BinaryAnalysisStatus.COMPLETE
    )
    return BinaryAnalysisResult(
        schema_version=SchemaVersion.VALUE_1_0_0,
        artifact_version_id=parent_version_id,
        analyzed_artifact_version_id=analyzed_version_id,
        format=aggregate.metadata.format,
        architecture=aggregate.metadata.architecture,
        bits=aggregate.metadata.bits,
        endianness=aggregate.metadata.endianness,
        image_base=aggregate.metadata.image_base,
        entry_point=aggregate.metadata.entry_point,
        compiler=aggregate.compiler,
        packer=aggregate.packer,
        packed=aggregate.packed,
        sections=list(aggregate.metadata.sections),
        functions=sorted(aggregate.functions, key=lambda item: (item["address"], item["name"])),
        instructions=sorted(aggregate.instructions, key=lambda item: item["address"]),
        strings=aggregate.strings,
        imports=aggregate.imports,
        tool_runs=aggregate.tool_runs,
        status=status,
        created_at=created_at,
    )


def _header_run() -> BinaryToolRun:
    return BinaryToolRun(
        tool_name="binary-header",
        tool_version="1.0.0",
        status=StaticToolStatus.SUCCEEDED,
        exit_code=0,
        reason=None,
        raw_output=None,
    )


def _tool_name(job: Job) -> str:
    value = job.get("tool")
    name = value.get("name") if isinstance(value, Mapping) else None
    return name if isinstance(name, str) else ""


def _tool_identity(job: Job) -> ToolIdentity:
    value = job.get("tool")
    if not isinstance(value, Mapping):
        return ToolIdentity(name="binary-import", version="1.0.0", image_digest=None)
    return ToolIdentity(
        name=str(value.get("name") or "binary-import"),
        version=str(value.get("version") or "1.0.0"),
        image_digest=(
            value.get("image_digest") if isinstance(value.get("image_digest"), str) else None
        ),
    )


def _required_argument(job: Job, name: str) -> str:
    arguments = job.get("arguments")
    value = arguments.get(name) if isinstance(arguments, Mapping) else None
    if not isinstance(value, str) or not value:
        raise BinaryAnalysisExecutionError(
            "binary_import.invalid_arguments",
            f"binary import argument {name!r} is required",
            details={"argument": name},
        )
    return value


def _single_input(job: Job) -> str:
    if len(job["input_refs"]) != 1:
        raise BinaryAnalysisExecutionError(
            "binary_import.invalid_input_count", "binary import requires exactly one input object"
        )
    return job["input_refs"][0]


def _derived_identifier(prefix: str, job_id: str, role: str) -> str:
    digest = hashlib.sha256(f"{job_id}\0{role}".encode()).hexdigest()[:32]
    return f"{prefix}:{digest}"


def _put_path(store: LocalContentAddressedStore, path: Path, max_bytes: int) -> StoredObject:
    with path.open("rb") as stream:
        return store.put_stream(stream, max_bytes=max_bytes)


def _cancelled_result(job_id: str, produced: list[str] | None = None) -> WorkerResult:
    return WorkerResult(
        schema_version=SchemaVersion.VALUE_1_0_0,
        job_id=job_id,
        status=JobStatus.CANCELLED,
        produced_artifact_version_ids=produced or [],
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
