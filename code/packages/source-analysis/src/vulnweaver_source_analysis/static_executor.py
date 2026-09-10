"""Static analysis execution and trusted follow-up Job scheduling."""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import shutil
import tempfile
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from vulnweaver_artifact_store import LocalContentAddressedStore
from vulnweaver_contracts import (
    Artifact,
    ArtifactKind,
    ArtifactVersion,
    FailureKind,
    Job,
    JobKind,
    JobRequestedEvent,
    JobStatus,
    JsonObject,
    SchemaVersion,
    SourceImportResult,
    StaticAnalysisDiagnostic,
    StaticAnalysisResult,
    StaticToolStatus,
    StructuredFailure,
    ToolIdentity,
    ToolSpec,
    WorkerResult,
    validate_contract,
)
from vulnweaver_persistence import (
    Database,
    EntityConflict,
    EntityNotFound,
    PersistenceError,
)
from vulnweaver_tool_runtime import bounded_resource_budget

from vulnweaver_source_analysis.archive import SafeArchiveImporter, SourceImportError
from vulnweaver_source_analysis.finding_projection import StaticFindingProjector
from vulnweaver_source_analysis.static_tools import (
    CppcheckAdapter,
    SemgrepAdapter,
    StaticToolAdapter,
    StaticToolOutput,
    StaticToolOutputError,
)


class StaticAnalysisExecutionError(RuntimeError):
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


class StaticAnalysisExecutor:
    """Run one fixed static tool and publish an immutable structured result."""

    def __init__(
        self,
        database: Database,
        store: LocalContentAddressedStore,
        *,
        importer: SafeArchiveImporter | None = None,
        adapters: Mapping[str, StaticToolAdapter] | None = None,
        scratch_root: str | Path | None = None,
        finding_projector: StaticFindingProjector | None = None,
    ) -> None:
        self._database = database
        self._store = store
        self._importer = importer or SafeArchiveImporter()
        self._adapters = dict(
            adapters or {"semgrep": SemgrepAdapter(), "cppcheck": CppcheckAdapter()}
        )
        self._scratch_root = Path(scratch_root) if scratch_root is not None else None
        self._finding_projector = finding_projector or StaticFindingProjector(database)

    async def execute(self, job: Job, cancellation: asyncio.Event) -> WorkerResult:
        try:
            return await self._execute(job, cancellation)
        except SourceImportError as error:
            return _failed_result(
                job["id"], f"static_analysis.{error.code}", error.message, error.details
            )
        except StaticAnalysisExecutionError as error:
            return _failed_result(
                job["id"], error.code, str(error), error.details, error.kind, error.retryable
            )
        except (OSError, TimeoutError) as error:
            return _failed_result(
                job["id"],
                "static_analysis.environment_error",
                "static analysis storage or scratch environment failed",
                {"exception_type": type(error).__name__},
                FailureKind.ENVIRONMENT,
                True,
            )
        except ValueError as error:
            return _failed_result(
                job["id"], "static_analysis.result_validation_failed", str(error), {}
            )
        except IntegrityError as error:
            return _failed_result(
                job["id"],
                "static_analysis.persistence_integrity_failed",
                "static analysis persistence integrity check failed",
                {"exception_type": type(error).__name__},
                FailureKind.INTERNAL,
            )
        except PersistenceError as error:
            return _failed_result(
                job["id"],
                f"static_analysis.{error.code}",
                error.message,
                error.details,
                FailureKind.INTERNAL,
                error.retryable,
            )
        except SQLAlchemyError as error:
            return _failed_result(
                job["id"],
                "static_analysis.persistence_unavailable",
                "static analysis persistence operation failed",
                {"exception_type": type(error).__name__},
                FailureKind.ENVIRONMENT,
                True,
            )

    async def _execute(self, job: Job, cancellation: asyncio.Event) -> WorkerResult:
        if job["kind"] != JobKind.SOURCE_ANALYSIS:
            raise StaticAnalysisExecutionError(
                "static_analysis.invalid_job_kind",
                "static executor received a non-source-analysis job",
            )
        tool_name = _tool_name(job)
        adapter = self._adapters.get(tool_name)
        if adapter is None:
            raise StaticAnalysisExecutionError(
                "static_analysis.tool_not_supported",
                "static executor received an unregistered tool name",
                details={"tool_name": tool_name},
            )
        artifact_version_id = _required_argument(job, "artifact_version_id")
        source_index_version_id = (
            _optional_argument(job, "source_index_version_id") or artifact_version_id
        )
        object_ref = _single_input(job)
        languages = _languages(job)
        if cancellation.is_set():
            return _cancelled_result(job["id"])

        scratch = Path(tempfile.mkdtemp(prefix="vulnweaver-static-", dir=self._scratch_root))
        try:
            extracted = scratch / "tree"
            await asyncio.to_thread(self._extract_archive, object_ref, extracted)
            if cancellation.is_set():
                return _cancelled_result(job["id"])
            output = await asyncio.to_thread(
                self._run_adapter,
                adapter,
                extracted,
                job["resource_budget"]["timeout_seconds"],
                min(job["resource_budget"]["disk_bytes"], 16 * 1024 * 1024),
                languages,
            )
            output, diagnostics = _parse_output(
                output,
                adapter,
                artifact_version_id=artifact_version_id,
            )
            result = _result(
                tool_name,
                output,
                diagnostics,
                artifact_version_id=artifact_version_id,
                created_at=job["created_at"],
            )
            validate_contract("StaticAnalysisResult", result)
            derived_version_id = _stable_identifier("artifact-version", job["id"])
            result_version = await self._publish_result(
                job,
                result,
                artifact_version_id,
                source_index_version_id,
                derived_version_id,
            )
            if output.status is not StaticToolStatus.SUCCEEDED:
                return _tool_failed_result(job["id"], output, derived_version_id)
            projection = await self._finding_projector.project(job, result, result_version)
            return WorkerResult(
                schema_version=SchemaVersion.VALUE_1_0_0,
                job_id=job["id"],
                status=JobStatus.SUCCEEDED,
                produced_artifact_version_ids=[derived_version_id],
                evidence_ids=list(projection.evidence_ids),
                failure=None,
            )
        finally:
            shutil.rmtree(scratch, ignore_errors=True)

    def _extract_archive(self, object_ref: str, extracted: Path) -> None:
        with self._store.open(object_ref) as archive_stream:
            self._importer.extract(archive_stream, extracted)

    @staticmethod
    def _run_adapter(
        adapter: StaticToolAdapter,
        root: Path,
        timeout_seconds: int,
        max_output_bytes: int,
        languages: set[str],
    ) -> StaticToolOutput:
        supported = {
            "semgrep": {"c", "cpp", "python", "java"},
            "cppcheck": {"c", "cpp"},
        }.get(adapter.name, set())
        if not languages.intersection(supported):
            return StaticToolOutput(
                adapter.name,
                None,
                StaticToolStatus.UNAVAILABLE,
                None,
                b"",
                b"",
                "language_not_detected",
            )
        return adapter.run(
            root,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
        )

    async def _publish_result(
        self,
        job: Job,
        result: StaticAnalysisResult,
        parent_version_id: str,
        source_index_version_id: str,
        version_id: str,
    ) -> ArtifactVersion:
        encoded = json.dumps(
            result, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode()
        stored = await asyncio.to_thread(
            self._store.put_stream, io.BytesIO(encoded), max_bytes=len(encoded)
        )
        artifact_id = _stable_identifier("artifact", job["id"])
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
                        "format": "static-analysis-result",
                        "tool": _tool_name(job),
                        "source_index_version_id": source_index_version_id,
                    },
                    created_at=job["created_at"],
                )
                validate_contract("Artifact", artifact)
                validate_contract("ArtifactVersion", version)
                await repositories.artifacts.add(artifact)
                await repositories.artifacts.add_version(version)
                return version
        except EntityNotFound as error:
            raise StaticAnalysisExecutionError(
                "static_analysis.parent_artifact_missing",
                "static analysis parent artifact disappeared",
                kind=FailureKind.INTERNAL,
            ) from error
        except EntityConflict as error:
            async with self._database.transaction() as repositories:
                existing = await repositories.artifacts.get_version(version_id)
                if (
                    existing["artifact_id"] != artifact_id
                    or existing["digest"] != stored.digest
                    or existing.get("parent_version_id") != parent_version_id
                ):
                    raise StaticAnalysisExecutionError(
                        "static_analysis.derived_artifact_conflict",
                        "deterministic static result conflicts with existing metadata",
                        kind=FailureKind.INTERNAL,
                    ) from error
                return existing


class StaticAnalysisScheduler:
    """Create trusted follow-up jobs after a successful source import."""

    def __init__(
        self,
        database: Database,
        specs: Mapping[str, ToolSpec],
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._database = database
        self._specs = dict(specs)
        self._clock = clock or (lambda: datetime.now(UTC))

    async def schedule(
        self,
        import_job: Job,
        source_result: SourceImportResult,
        source_version_id: str,
    ) -> tuple[str, ...]:
        languages = set(source_result["capability_profile"]["languages"])
        selected = [name for name in ("semgrep", "cppcheck") if name in self._specs]
        selected = [
            name
            for name in selected
            if languages.intersection(
                {"c", "cpp"} if name == "cppcheck" else {"c", "cpp", "python", "java"}
            )
        ]
        created: list[str] = []
        now = _timestamp(self._clock())
        async with self._database.transaction() as repositories:
            for tool_name in selected:
                spec = self._specs[tool_name]
                job_id = _stable_identifier("job", import_job["id"], tool_name)
                job = Job(
                    schema_version=SchemaVersion.VALUE_1_0_0,
                    id=job_id,
                    task_id=import_job["task_id"],
                    kind=JobKind.SOURCE_ANALYSIS,
                    tool={
                        "name": spec["name"],
                        "version": spec["version"],
                        "image_digest": spec["image_digest"],
                    },
                    arguments=cast(
                        JsonObject,
                        {
                            "artifact_version_id": _required_argument(
                                import_job, "artifact_version_id"
                            ),
                            "source_index_version_id": source_version_id,
                            "languages": sorted(languages),
                        },
                    ),
                    input_refs=import_job["input_refs"],
                    status=JobStatus.QUEUED,
                    idempotency_key=_stable_identifier(
                        "static-analysis", import_job["id"], tool_name
                    ),
                    resource_budget=bounded_resource_budget(
                        import_job["resource_budget"], spec["resource_limits"]
                    ),
                    retry_policy=spec["retry_policy"],
                    attempt=0,
                    lease=None,
                    failure=None,
                    created_at=now,
                    updated_at=now,
                )
                event = JobRequestedEvent(
                    schema_version=SchemaVersion.VALUE_1_0_0,
                    event_id=_stable_identifier("event", job_id, "requested"),
                    event_type="job.requested",
                    aggregate_id=job_id,
                    sequence=0,
                    occurred_at=now,
                    correlation_id=job["task_id"],
                    causation_id=import_job["id"],
                    payload={
                        "job_id": job_id,
                        "task_id": job["task_id"],
                        "job_kind": job["kind"],
                        "attempt": 0,
                    },
                )
                await repositories.jobs.enqueue_with_outbox(job, event)
                created.append(job_id)
        return tuple(created)


def _result(
    tool_name: str,
    output: StaticToolOutput,
    diagnostics: list[StaticAnalysisDiagnostic],
    *,
    artifact_version_id: str,
    created_at: str,
) -> StaticAnalysisResult:
    return StaticAnalysisResult(
        schema_version=SchemaVersion.VALUE_1_0_0,
        artifact_version_id=artifact_version_id,
        diagnostics=diagnostics,
        tool_runs=[
            {
                "tool_name": tool_name,
                "tool_version": output.tool_version,
                "status": output.status,
                "exit_code": output.exit_code,
                "reason": output.reason,
            }
        ],
        created_at=created_at,
    )


def _parse_output(
    output: StaticToolOutput,
    adapter: StaticToolAdapter,
    *,
    artifact_version_id: str,
) -> tuple[StaticToolOutput, list[StaticAnalysisDiagnostic]]:
    if output.status is not StaticToolStatus.SUCCEEDED:
        return output, []
    try:
        return output, adapter.parse(output, artifact_version_id=artifact_version_id)
    except StaticToolOutputError as error:
        return (
            StaticToolOutput(
                tool_name=output.tool_name,
                tool_version=output.tool_version,
                status=StaticToolStatus.FAILED,
                exit_code=output.exit_code,
                stdout=output.stdout,
                stderr=output.stderr,
                reason=error.code,
            ),
            [],
        )


def _tool_failed_result(
    job_id: str, output: StaticToolOutput, result_version_id: str
) -> WorkerResult:
    reason = output.reason or "tool_execution_failed"
    if reason == "timeout":
        kind = FailureKind.TIMEOUT
        retryable = True
        message = "static analysis tool timed out"
    elif output.status is StaticToolStatus.UNAVAILABLE:
        kind = FailureKind.DEPENDENCY
        retryable = True
        message = "static analysis tool is unavailable"
    elif reason in _INVALID_OUTPUT_REASONS:
        kind = FailureKind.TOOL
        retryable = False
        message = "static analysis tool produced an invalid result"
    else:
        kind = FailureKind.TOOL
        retryable = False
        message = "static analysis tool did not complete"
    details: dict[str, object] = {
        "tool_name": output.tool_name,
        "tool_status": str(output.status),
        "reason": reason,
        "result_artifact_version_id": result_version_id,
    }
    if output.exit_code is not None:
        details["exit_code"] = output.exit_code
    return _failed_result(
        job_id,
        f"static_analysis.{reason}",
        message,
        details,
        kind,
        retryable,
        produced_artifact_version_ids=[result_version_id],
    )


_INVALID_OUTPUT_REASONS = frozenset(
    {
        "semgrep.invalid_json_output",
        "semgrep.invalid_json_document",
        "semgrep.results_missing",
        "semgrep.invalid_result",
        "cppcheck.invalid_xml_output",
    }
)


def _tool_name(job: Job) -> str:
    tool = job.get("tool")
    name = tool.get("name") if isinstance(tool, Mapping) else None
    if not isinstance(name, str) or not name:
        raise StaticAnalysisExecutionError(
            "static_analysis.invalid_tool", "static analysis tool is required"
        )
    return name


def _tool_identity(job: Job) -> ToolIdentity:
    tool = job.get("tool")
    if not isinstance(tool, Mapping):
        raise StaticAnalysisExecutionError(
            "static_analysis.invalid_tool", "static analysis tool is required"
        )
    return ToolIdentity(
        name=tool["name"],
        version=tool["version"],
        image_digest=tool.get("image_digest"),
    )


def _single_input(job: Job) -> str:
    if len(job["input_refs"]) != 1:
        raise StaticAnalysisExecutionError(
            "static_analysis.invalid_input_count", "static analysis requires one input"
        )
    return job["input_refs"][0]


def _required_argument(job: Job, name: str) -> str:
    arguments = job.get("arguments")
    value = arguments.get(name) if isinstance(arguments, Mapping) else None
    if not isinstance(value, str) or not value:
        raise StaticAnalysisExecutionError(
            "static_analysis.invalid_arguments", f"argument {name!r} is required"
        )
    return value


def _optional_argument(job: Job, name: str) -> str | None:
    arguments = job.get("arguments")
    value = arguments.get(name) if isinstance(arguments, Mapping) else None
    return value if isinstance(value, str) and value else None


def _languages(job: Job) -> set[str]:
    arguments = job.get("arguments")
    value = arguments.get("languages") if isinstance(arguments, Mapping) else None
    return {item for item in value if isinstance(item, str)} if isinstance(value, list) else set()


def _stable_identifier(prefix: str, *parts: str) -> str:
    return f"{prefix}:{hashlib.sha256(chr(0).join(parts).encode()).hexdigest()[:32]}"


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


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
    code: str,
    message: str,
    details: Mapping[str, object],
    kind: FailureKind = FailureKind.VALIDATION,
    retryable: bool = False,
    produced_artifact_version_ids: list[str] | None = None,
) -> WorkerResult:
    return WorkerResult(
        schema_version=SchemaVersion.VALUE_1_0_0,
        job_id=job_id,
        status=JobStatus.FAILED,
        produced_artifact_version_ids=produced_artifact_version_ids or [],
        evidence_ids=[],
        failure=StructuredFailure(
            code=code,
            kind=kind,
            message=message,
            retryable=retryable,
            details=cast(JsonObject, dict(details)),
        ),
    )
