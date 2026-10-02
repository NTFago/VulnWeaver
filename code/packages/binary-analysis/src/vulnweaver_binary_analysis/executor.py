"""Binary import executor for the shared reliable Worker SDK."""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import logging
import shutil
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import IO, Protocol, cast

from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from vulnweaver_artifact_store import ArtifactStoreError, LocalContentAddressedStore, StoredObject
from vulnweaver_contracts import (
    Artifact,
    ArtifactKind,
    ArtifactVersion,
    BinaryAnalysisResult,
    BinaryAnalysisStatus,
    BinaryPseudocode,
    BinaryToolRun,
    FailureKind,
    Job,
    JobKind,
    JobStatus,
    JsonObject,
    SchemaVersion,
    StaticToolStatus,
    StructuredFailure,
    Task,
    ToolIdentity,
    WorkerResult,
    validate_contract,
)
from vulnweaver_pair import BinaryPairImporter, BinaryPairImportError
from vulnweaver_persistence import Database, EntityConflict, EntityNotFound, PersistenceError

from vulnweaver_binary_analysis.critical_logic import (
    CriticalLogicCandidate,
    discover_critical_logic,
)
from vulnweaver_binary_analysis.deobfuscation import (
    recover_readable_pseudocode,
    validate_model_readable_pseudocode,
)
from vulnweaver_binary_analysis.headers import (
    BinaryInspectionError,
    extract_strings,
    inspect_binary,
)
from vulnweaver_binary_analysis.obfuscation import (
    ObfuscationAssessment,
    assess_control_flow_flattening,
)
from vulnweaver_binary_analysis.tools import (
    AngrAdapter,
    BinaryFactsAdapter,
    BinaryFactsSandbox,
    BinaryToolAdapter,
    DetectItEasyAdapter,
    GhidraHeadlessAdapter,
    ObjdumpAdapter,
    ToolCancelled,
    ToolExecutionError,
    UpxAdapter,
)
from vulnweaver_binary_analysis.types import (
    BinaryAnalysisAggregate,
    BinaryAnalysisLimits,
    BinaryMetadata,
)
from vulnweaver_binary_analysis.unpacking import (
    BinaryUnpackSandboxAdapter,
    LiefRebuilder,
    UnpackChainOutcome,
    Unpacker,
    UnpackerChain,
    UpxCliUnpacker,
    XorRegionUnpacker,
)

LOGGER = logging.getLogger("vulnweaver.binary_analysis")

# Derived-artifact identity per final unpacking method.  UPX keeps its
# historical role and format so existing provenance stays readable.
_UNPACK_DERIVATIONS: dict[str, tuple[str, str, str]] = {
    "upx": ("upx-unpacked", "upx-unpacked-binary", "upx"),
    "de4dot": ("de4dot-cleaned", "dotnet-cleaned-assembly", "de4dot"),
    "unipacker": ("emulated-unpacked", "emulated-unpacked-binary", "unipacker"),
    "xor-recovery": ("xor-recovered", "xor-recovered-binary", "xor-recovery"),
}


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


class CriticalLogicHook(Protocol):
    """Confirm stamped critical-logic candidates via the planning model."""

    async def confirm(
        self, *, task_id: str, job_id: str, candidates: JsonObject
    ) -> dict[str, list[JsonObject]]: ...


class AngrRunner(Protocol):
    """Execute targeted symbolic analysis for the planning agent."""

    async def __call__(self, target_addresses: tuple[int, ...]) -> JsonObject: ...


class BinaryPlanningHook(Protocol):
    """Model-driven planning step executed after the facts baseline."""

    async def plan(
        self, job: Job, facts: JsonObject, run_angr: AngrRunner
    ) -> tuple[int, ...]: ...


class ReadablePseudocodeHook(Protocol):
    """Optional model pass producing an anchored, review-only pseudocode view."""

    async def render(
        self,
        job: Job,
        pseudocode: tuple[BinaryPseudocode, ...],
        obfuscation: JsonObject,
    ) -> Sequence[Mapping[str, object]]: ...


class BinaryImportExecutor:
    """Inspect one registered ELF/PE and publish immutable normalized analysis."""

    def __init__(
        self,
        database: Database,
        store: LocalContentAddressedStore,
        *,
        limits: BinaryAnalysisLimits | None = None,
        adapters: Sequence[BinaryToolAdapter] | None = None,
        unpackers: Sequence[Unpacker] | None = None,
        rebuilder: LiefRebuilder | None = None,
        pair_importer: BinaryPairImporter | None = None,
        scratch_root: str | Path | None = None,
        sandbox: BinaryFactsSandbox | None = None,
        sandbox_image_digest: str | None = None,
        planning_hook: BinaryPlanningHook | None = None,
        critical_logic_hook: CriticalLogicHook | None = None,
        readable_pseudocode_hook: ReadablePseudocodeHook | None = None,
    ) -> None:
        self._database = database
        self._store = store
        self._limits = limits or BinaryAnalysisLimits()
        self._adapters = tuple(adapters) if adapters is not None else (ObjdumpAdapter(),)
        self._unpacker_chain = UnpackerChain(
            unpackers if unpackers is not None else (UpxCliUnpacker(), XorRegionUnpacker()),
            rebuilder=rebuilder if rebuilder is not None else LiefRebuilder(),
        )
        self._pair_importer = pair_importer
        self._scratch_root = Path(scratch_root) if scratch_root is not None else None
        self._sandbox = sandbox
        self._sandbox_image_digest = sandbox_image_digest
        self._planning_hook = planning_hook
        self._critical_logic_hook = critical_logic_hook
        self._readable_pseudocode_hook = readable_pseudocode_hook
        self._angr_adapter = next(
            (adapter for adapter in self._adapters if isinstance(adapter, AngrAdapter)),
            None,
        )

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
        pair_importer: BinaryPairImporter | None = None,
        sandbox: BinaryFactsSandbox | None = None,
        sandbox_image_digest: str | None = None,
        planning_hook: BinaryPlanningHook | None = None,
        critical_logic_hook: CriticalLogicHook | None = None,
        readable_pseudocode_hook: ReadablePseudocodeHook | None = None,
        limits: BinaryAnalysisLimits | None = None,
    ) -> BinaryImportExecutor:
        return cls(
            database,
            store,
            limits=limits,
            adapters=(
                DetectItEasyAdapter(die_executable),
                ObjdumpAdapter(objdump_executable),
                GhidraHeadlessAdapter(ghidra_executable, ghidra_script_directory),
                AngrAdapter(angr_enabled),
            ),
            # The worker-local chain stays cheap and static: UPX plus pure-Python
            # XOR recovery.  Emulated and .NET unpacking live in the isolated
            # binary-tools image and are reached through the sandbox fallback.
            unpackers=(
                UpxCliUnpacker(UpxAdapter(upx_executable)),
                XorRegionUnpacker(),
            ),
            pair_importer=pair_importer,
            scratch_root=scratch_root,
            sandbox=sandbox,
            sandbox_image_digest=sandbox_image_digest,
            planning_hook=planning_hook,
            critical_logic_hook=critical_logic_hook,
            readable_pseudocode_hook=readable_pseudocode_hook,
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
        except ToolExecutionError as error:
            # Sandbox failures carry their own failure kind: a runner timeout or
            # transport error is retryable under the job retry policy, while a
            # tool exit is not. Without this mapping the error used to escape to
            # the worker's generic internal handler, which never retried.
            failure_code = str(error.details.get("failure_code") or "tool_execution_failed")
            return _failed_result(
                job["id"],
                code=f"binary_import.{failure_code.replace('.', '_')}",
                kind=error.kind,
                message=str(error),
                retryable=error.retryable,
                details=error.details,
            )
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

    async def _plan_with_agent(
        self,
        job: Job,
        aggregate: BinaryAnalysisAggregate,
        analyzed_path: Path,
        metadata: BinaryMetadata,
        cancellation: asyncio.Event,
        produced: list[str],
        analyzed_object_ref: str,
    ) -> tuple[int, ...] | None:
        """Run the model planning hook; failures degrade instead of aborting."""
        planning_hook = self._planning_hook
        assert planning_hook is not None

        async def run_angr(target_addresses: tuple[int, ...]) -> JsonObject:
            _validate_symbolic_targets(target_addresses, metadata)
            if self._sandbox is not None and self._sandbox_image_digest is not None:
                contribution = await BinaryFactsAdapter(
                    self._sandbox,
                    self._store,
                    image_digest=self._sandbox_image_digest,
                    input_ref=analyzed_object_ref,
                    target_addresses=target_addresses,
                    angr_enabled=True,
                ).analyze(analyzed_path, metadata, self._limits, cancellation)
            else:
                angr_adapter = self._angr_adapter
                assert angr_adapter is not None
                contribution = await angr_adapter.analyze_targets(
                    analyzed_path,
                    metadata,
                    self._limits,
                    cancellation,
                    target_addresses,
                )
            aggregate.merge(contribution, self._limits)
            explored = [
                fact
                for fact in aggregate.symbolic_facts
                if fact["function_address"] in target_addresses
            ]
            return {
                "targets": list(target_addresses),
                "status": "completed",
                "symbolic_facts": len(explored),
            }

        facts = _planning_facts(job, aggregate)
        try:
            return await planning_hook.plan(job, facts, run_angr)
        except Exception as error:  # planning degrades, never aborts the job
            LOGGER.warning(
                "binary_planning_degraded",
                extra={"job_id": job["id"], "error": str(error)[:200]},
            )
            return ()


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
        target_addresses = _target_addresses(job, self._limits)
        object_ref = _single_input(job)
        task = await self._validate_input(job, parent_version_id, object_ref)
        reused = await self._find_reusable(
            job,
            project_id=task["project_id"],
            object_ref=object_ref,
            target_addresses=target_addresses,
        )
        if reused is not None:
            return WorkerResult(
                schema_version=SchemaVersion.VALUE_1_0_0,
                job_id=job["id"],
                status=JobStatus.SUCCEEDED,
                produced_artifact_version_ids=reused,
                evidence_ids=[],
                failure=None,
            )
        if cancellation.is_set():
            return _cancelled_result(job["id"])

        scratch = Path(tempfile.mkdtemp(prefix="vulnweaver-binary-", dir=self._scratch_root))
        try:
            input_path = scratch / "input.bin"
            await asyncio.to_thread(self._copy_input, object_ref, input_path)
            original_metadata = await asyncio.to_thread(inspect_binary, input_path, self._limits)
            aggregate = BinaryAnalysisAggregate(original_metadata)
            aggregate.tool_runs.append(_header_run())

            unpack_outcome = await self._unpacker_chain.run(
                input_path, original_metadata, self._limits, cancellation
            )
            aggregate.tool_runs.extend(unpack_outcome.runs)
            if (
                unpack_outcome.unpacked_path is None
                and original_metadata.packed
                and self._sandbox is not None
                and self._sandbox_image_digest is not None
            ):
                # The local chain only holds static strategies; everything that
                # needs the fuller toolchain (emulation, .NET cleaning, LIEF
                # rebuild) runs in the isolated binary-tools image.
                sandbox_outcome = await self._try_sandbox_unpack(
                    scratch, object_ref, original_metadata, cancellation
                )
                if sandbox_outcome is not None:
                    unpack_outcome = sandbox_outcome
                    aggregate.tool_runs.extend(sandbox_outcome.runs)
            analyzed_path = input_path
            analyzed_version_id = parent_version_id
            # The sandbox tooling consumes the artifact by CAS reference, not by
            # the local path.  Once unpacking replaces `analyzed_path` with the
            # unpacked image, this reference must move with it, or every sandbox
            # analysis silently keeps reading the packed file.
            analyzed_object_ref = object_ref
            produced: list[str] = []
            metadata = original_metadata
            if unpack_outcome.unpacked_path is not None:
                assert unpack_outcome.final_metadata is not None
                metadata = unpack_outcome.final_metadata
                _validate_symbolic_targets(target_addresses, metadata)
                method = unpack_outcome.method or "unknown"
                role, unpack_format, tool_name = _UNPACK_DERIVATIONS.get(
                    method, ("unpacked", "unpacked-binary", method)
                )
                unpacked_version_id = _derived_identifier("artifact-version", job["id"], role)
                unpacked_artifact_id = _derived_identifier("artifact", job["id"], role)
                stored_unpacked = unpack_outcome.stored
                if stored_unpacked is None:
                    stored_unpacked = await asyncio.to_thread(
                        _put_path,
                        self._store,
                        unpack_outcome.unpacked_path,
                        self._limits.max_input_bytes,
                    )
                await self._register_derived(
                    job,
                    parent_version_id=parent_version_id,
                    artifact_id=unpacked_artifact_id,
                    version_id=unpacked_version_id,
                    stored=stored_unpacked,
                    generation_config={
                        "format": unpack_format,
                        "tool": tool_name,
                        "methods": list(unpack_outcome.methods),
                        "rounds": unpack_outcome.rounds,
                        "source_artifact_version_id": parent_version_id,
                    },
                )
                analyzed_path = unpack_outcome.unpacked_path
                analyzed_version_id = unpacked_version_id
                analyzed_object_ref = stored_unpacked.object_ref
                produced.append(unpacked_version_id)
                aggregate = BinaryAnalysisAggregate(metadata)
                aggregate.packed = True
                aggregate.packer = original_metadata.packer or (
                    "UPX" if method == "upx" else method
                )
                aggregate.tool_runs.extend((_header_run(), *unpack_outcome.runs))
            elif original_metadata.packed:
                aggregate.packed = True

            _validate_symbolic_targets(target_addresses, metadata)
            aggregate.strings = list(
                await asyncio.to_thread(extract_strings, analyzed_path, metadata, self._limits)
            )
            adapters: Sequence[BinaryToolAdapter] = self._adapters
            if self._sandbox is not None and self._sandbox_image_digest:
                adapters = (
                    BinaryFactsAdapter(
                        self._sandbox,
                        self._store,
                        image_digest=self._sandbox_image_digest,
                        input_ref=analyzed_object_ref,
                        target_addresses=target_addresses,
                        angr_enabled=(
                            self._angr_adapter.enabled
                            if self._angr_adapter is not None
                            else False
                        ),
                    ),
                )
            planning_active = self._planning_active()
            for adapter in adapters:
                if cancellation.is_set():
                    return _cancelled_result(job["id"], produced)
                if planning_active and adapter is self._angr_adapter:
                    # With planning enabled angr runs after the model selected
                    # its targets instead of the fixed empty-target pass.
                    continue
                if isinstance(adapter, AngrAdapter):
                    contribution = await adapter.analyze_targets(
                        analyzed_path,
                        metadata,
                        self._limits,
                        cancellation,
                        target_addresses,
                    )
                else:
                    contribution = await adapter.analyze(
                        analyzed_path, metadata, self._limits, cancellation
                    )
                aggregate.merge(contribution, self._limits)

            if planning_active and not cancellation.is_set():
                assert self._planning_hook is not None
                planned = await self._plan_with_agent(
                    job,
                    aggregate,
                    analyzed_path,
                    metadata,
                    cancellation,
                    produced,
                    analyzed_object_ref,
                )
                if planned is None:
                    return _cancelled_result(job["id"], produced)
                target_addresses = _merge_target_addresses(target_addresses, planned)

            _attach_critical_logic_candidates(aggregate, self._limits)
            if self._critical_logic_hook is not None:
                await _confirm_critical_logic(
                    job, aggregate, self._critical_logic_hook
                )

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
                    "target_addresses": list(target_addresses),
                    # Future imports over the same input adopt this result only
                    # when their own fingerprint matches byte-for-byte inputs.
                    "reuse_key": self._reuse_key(job, target_addresses),
                },
            )
            produced.append(result_version_id)
            if cancellation.is_set():
                return _cancelled_result(job["id"], produced)
            readable_version_id = await self._publish_readable_pseudocode(
                job, result_version_id, aggregate
            )
            if readable_version_id is not None:
                produced.append(readable_version_id)
            if self._pair_importer is not None:
                try:
                    await self._pair_importer.import_binary_result(
                        result,
                        raw_object_ref=stored_result.object_ref,
                        tool=_tool_identity(job),
                        created_at=job["created_at"],
                    )
                except BinaryPairImportError as error:
                    return _failed_result(
                        job["id"],
                        code="binary_import.pair_validation_failed",
                        kind=FailureKind.INTERNAL,
                        message=str(error),
                        retryable=False,
                        produced_artifact_version_ids=produced,
                    )
                except IntegrityError as error:
                    return _failed_result(
                        job["id"],
                        code="binary_import.pair_integrity_failed",
                        kind=FailureKind.INTERNAL,
                        message="binary result was published but PAIR integrity validation failed",
                        retryable=False,
                        details={"exception_type": type(error).__name__},
                        produced_artifact_version_ids=produced,
                    )
                except (PersistenceError, SQLAlchemyError) as error:
                    return _failed_result(
                        job["id"],
                        code="binary_import.pair_persistence_failed",
                        kind=FailureKind.ENVIRONMENT,
                        message="binary result was published but PAIR persistence failed",
                        retryable=True,
                        details={"exception_type": type(error).__name__},
                        produced_artifact_version_ids=produced,
                    )
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

    async def _publish_readable_pseudocode(
        self, job: Job, analysis_version_id: str, aggregate: BinaryAnalysisAggregate
    ) -> str | None:
        """Publish a bounded review artifact without changing decompiler evidence."""
        max_chars = min(32 * 1024, self._limits.max_pseudocode_chars)
        source = _bounded_readable_source(
            aggregate.pseudocode,
            max_chars=max_chars,
            # The artifact contains raw excerpts plus deterministic and optional
            # model views.  Keep substantial headroom for JSON escaping/metadata.
            total_chars=self._limits.max_tool_output_bytes // 16,
        )
        if not source:
            return None
        assessments = assess_control_flow_flattening(aggregate.basic_blocks, aggregate.xrefs)
        recovered = recover_readable_pseudocode(source, assessments, max_chars=max_chars)
        model_view: tuple[BinaryPseudocode, ...] = ()
        if self._readable_pseudocode_hook is not None:
            try:
                candidates = await self._readable_pseudocode_hook.render(
                    job, source, _obfuscation_document(assessments)
                )
                model_view = validate_model_readable_pseudocode(
                    source, candidates, max_chars=max_chars
                )
            except Exception as error:  # Readability is advisory and must not lose evidence.
                LOGGER.warning(
                    "binary_readable_pseudocode_degraded",
                    extra={"job_id": job["id"], "error": type(error).__name__},
                )
        document = {
            "schema_version": "1.0.0",
            "analysis_artifact_version_id": analysis_version_id,
            "original_pseudocode_excerpts": list(source),
            "recovered_pseudocode": list(recovered),
            "model_pseudocode": list(model_view),
            "obfuscation": _obfuscation_document(assessments)["assessments"],
            "truncated_function_count": max(0, len(aggregate.pseudocode) - len(source)),
        }
        content = json.dumps(
            document, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        if len(content) > self._limits.max_tool_output_bytes:
            raise BinaryAnalysisExecutionError(
                "binary_import.readable_pseudocode_too_large",
                "bounded readable pseudocode artifact exceeds the output limit",
                kind=FailureKind.INTERNAL,
            )
        stored = await asyncio.to_thread(
            self._store.put_stream, io.BytesIO(content), max_bytes=len(content)
        )
        version_id = _derived_identifier("artifact-version", job["id"], "readable-pseudocode")
        artifact_id = _derived_identifier("artifact", job["id"], "readable-pseudocode")
        await self._register_derived(
            job,
            parent_version_id=analysis_version_id,
            artifact_id=artifact_id,
            version_id=version_id,
            stored=stored,
            generation_config={
                "format": "binary-readable-pseudocode",
                "source_analysis_version_id": analysis_version_id,
                "recovery": "deterministic-control-flow-labeling",
                "model_view_count": len(model_view),
                "truncated_function_count": max(0, len(aggregate.pseudocode) - len(source)),
            },
        )
        return version_id

    async def _try_sandbox_unpack(
        self,
        scratch: Path,
        object_ref: str,
        metadata: BinaryMetadata,
        cancellation: asyncio.Event,
    ) -> UnpackChainOutcome | None:
        """Run the isolated binary-unpack tool; failures degrade, never abort."""
        assert self._sandbox is not None and self._sandbox_image_digest is not None
        try:
            outcome = await BinaryUnpackSandboxAdapter(
                self._sandbox,
                self._store,
                image_digest=self._sandbox_image_digest,
                input_ref=object_ref,
            ).unpack(cast(ArtifactKind, metadata.format), self._limits, cancellation)
        except ToolExecutionError as error:
            # The detail rides in the message: the default formatter drops
            # `extra` fields, and a name-only warning makes the failure
            # undiagnosable from the worker log.
            LOGGER.warning("binary_unpack_sandbox_degraded: %s", str(error)[:600])
            return None
        if outcome.stored is None:
            return outcome
        path = scratch / "sandbox-unpacked.bin"
        try:
            with self._store.open(outcome.stored.object_ref) as source:
                await asyncio.to_thread(_copy_stream, source, path)
            outcome.final_metadata = await asyncio.to_thread(
                inspect_binary, path, self._limits
            )
        except (OSError, BinaryInspectionError) as error:
            LOGGER.warning(
                "binary_unpack_sandbox_output_rejected",
                extra={"error": str(error)[:200]},
            )
            outcome.stored = None
            outcome.unpacked_path = None
            outcome.method = None
            outcome.methods = ()
            return outcome
        outcome.unpacked_path = path
        return outcome

    async def _validate_input(self, job: Job, version_id: str, object_ref: str) -> Task:
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
        return task

    def _planning_active(self) -> bool:
        return self._planning_hook is not None and (
            self._angr_adapter is not None
            or (self._sandbox is not None and self._sandbox_image_digest is not None)
        )

    def _reuse_key(self, job: Job, target_addresses: tuple[int, ...]) -> str:
        """Fingerprint of everything that shapes the analysis result bytes.

        Two runs may adopt one result only when every input that changes the
        output matches: the tool identity, which hooks and execution paths are
        active, the requested symbolic targets, and the limits that bound what
        lands in the document.  Anything else — timeouts, scratch paths, pure
        performance knobs — must stay out of the key.
        """

        relevant_limits = {
            "max_functions": self._limits.max_functions,
            "max_instructions": self._limits.max_instructions,
            "max_basic_blocks": self._limits.max_basic_blocks,
            "max_xrefs": self._limits.max_xrefs,
            "max_pseudocode_functions": self._limits.max_pseudocode_functions,
            "max_pseudocode_chars": self._limits.max_pseudocode_chars,
            "max_symbolic_functions": self._limits.max_symbolic_functions,
            "max_symbolic_steps": self._limits.max_symbolic_steps,
            "max_symbolic_states": self._limits.max_symbolic_states,
            "max_strings": self._limits.max_strings,
            "max_string_chars": self._limits.max_string_chars,
            "min_string_chars": self._limits.min_string_chars,
        }
        tool = _tool_identity(job)
        material = {
            "tool": {"name": tool["name"], "version": tool["version"]},
            "sandboxed_facts": self._sandbox is not None and self._sandbox_image_digest is not None,
            "angr_enabled": bool(
                self._angr_adapter.enabled if self._angr_adapter is not None else False
            ),
            "planning_active": self._planning_active(),
            "critical_logic_hook": self._critical_logic_hook is not None,
            "readable_pseudocode_hook": self._readable_pseudocode_hook is not None,
            "target_addresses": list(target_addresses),
            "limits": relevant_limits,
        }
        encoded = json.dumps(material, sort_keys=True, separators=(",", ":"))
        return "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    async def _find_reusable(
        self,
        job: Job,
        *,
        project_id: str,
        object_ref: str,
        target_addresses: tuple[int, ...],
    ) -> list[str] | None:
        """Adopt a prior run's immutable results when the exact analysis repeats.

        Re-running a task over an already-analyzed upload used to redo the whole
        Ghidra/facts chain for byte-identical input. The earlier Job's produced
        versions are immutable and already carry their PAIR rows, so a match on
        the result-shaping fingerprint adopts them as-is; every mismatch (angr
        toggle, target set, tool version, limits) falls through to a full run.
        Versions registered before reuse keys existed simply never match.
        """

        fingerprint = self._reuse_key(job, target_addresses)
        try:
            async with self._database.transaction() as repositories:
                candidates = await repositories.jobs.find_reusable_imports(
                    object_ref, tool_name=_tool_name(job), project_id=project_id
                )
                for candidate in candidates:
                    for version_id in candidate.produced_artifact_version_ids:
                        version = await repositories.artifacts.get_version(version_id)
                        config = version.get("generation_config") or {}
                        if (
                            config.get("format") == "binary-analysis-result"
                            and config.get("reuse_key") == fingerprint
                        ):
                            LOGGER.info(
                                "binary_import_reused_prior_result",
                                extra={
                                    "job_id": job["id"],
                                    "reused_job_id": candidate.job_id,
                                    "reused_task_id": candidate.task_id,
                                    "version_count": len(
                                        candidate.produced_artifact_version_ids
                                    ),
                                },
                            )
                            return list(candidate.produced_artifact_version_ids)
        except (PersistenceError, SQLAlchemyError, AttributeError) as error:
            # Reuse is an optimization, never a precondition: a database outage
            # — or an executor wired without one — degrades to the ordinary
            # full import.
            LOGGER.warning(
                "binary_import_reuse_lookup_failed", extra={"error": str(error)[:200]}
            )
        return None

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
        basic_blocks=sorted(
            aggregate.basic_blocks,
            key=lambda item: (item["start_address"], item["end_address"]),
        ),
        xrefs=sorted(
            aggregate.xrefs,
            key=lambda item: (
                item["source_address"],
                item["target_address"],
                str(item["type"]),
            ),
        ),
        pseudocode=sorted(
            aggregate.pseudocode,
            key=lambda item: (item["address"], item["tool_name"]),
        ),
        symbolic_facts=sorted(
            aggregate.symbolic_facts,
            key=lambda item: item["function_address"],
        ),
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


def _attach_critical_logic_candidates(
    aggregate: BinaryAnalysisAggregate, limits: BinaryAnalysisLimits
) -> None:
    """Stamp deterministic auth/crypto/registration candidates into function attributes.

    Candidates stay advisory (``confirmed: None``); model confirmation may later
    replace the value without touching the immutable raw tool outputs.
    """
    candidates = discover_critical_logic(
        aggregate.functions, aggregate.imports, aggregate.strings
    )
    by_name: dict[str, list[CriticalLogicCandidate]] = {}
    for candidate in candidates:
        by_name.setdefault(candidate.function_name, []).append(candidate)
    stamped = 0
    for function in aggregate.functions:
        matched = by_name.get(function["name"])
        if not matched or stamped >= limits.max_functions:
            continue
        stamped += 1
        function["attributes"]["critical_logic"] = [
            {
                "category": item.category,
                "score": item.score,
                "evidence": list(item.evidence),
                "confirmed": None,
                "rationale": None,
            }
            for item in matched
        ]


async def _confirm_critical_logic(
    job: Job,
    aggregate: BinaryAnalysisAggregate,
    hook: CriticalLogicHook,
) -> None:
    """Merge model verdicts into the stamped candidate attributes."""
    candidates: JsonObject = {}
    for function in aggregate.functions:
        marked = function["attributes"].get("critical_logic")
        if isinstance(marked, list) and marked:
            candidates[function["name"]] = cast(JsonObject, {"entries": marked})
    if not candidates:
        return
    try:
        assessments = await hook.confirm(
            task_id=job["task_id"], job_id=job["id"], candidates=candidates
        )
    except Exception as error:  # confirmation degrades, never aborts the job
        LOGGER.warning(
            "critical_logic_confirmation_degraded",
            extra={"job_id": job["id"], "error": str(error)[:200]},
        )
        return
    for function in aggregate.functions:
        verdicts = assessments.get(function["name"])
        if not isinstance(verdicts, list):
            continue
        entries = function["attributes"].get("critical_logic")
        if not isinstance(entries, list):
            continue
        for candidate_entry in entries:
            if not isinstance(candidate_entry, dict):
                continue
            entry = cast(JsonObject, candidate_entry)
            for verdict in verdicts:
                if (
                    verdict.get("function_name") == function["name"]
                    and verdict.get("category") == entry.get("category")
                ):
                    entry["confirmed"] = bool(verdict.get("confirmed"))
                    entry["rationale"] = verdict.get("rationale")


def _merge_target_addresses(
    current: tuple[int, ...], planned: tuple[int, ...]
) -> tuple[int, ...]:
    """Union job-supplied and model-planned targets, bounded and order-stable."""
    merged = list(dict.fromkeys([*current, *planned]))
    return tuple(merged[:16])


def _planning_facts(job: Job, aggregate: BinaryAnalysisAggregate) -> JsonObject:
    """Bounded, service-owned facts the planning agent may reason about."""
    assessments = assess_control_flow_flattening(
        aggregate.basic_blocks, aggregate.xrefs
    )
    return cast(
        JsonObject,
        {
            "input_artifact_version_id": _required_argument(job, "artifact_version_id"),
            "packed": aggregate.packed,
            "packer": aggregate.packer,
            "function_count": len(aggregate.functions),
            "functions": [
                {"name": item["name"], "address": item["address"]}
                for item in aggregate.functions[:64]
            ],
            "obfuscation": _obfuscation_document(assessments)["assessments"],
            "basic_block_count": len(aggregate.basic_blocks),
            "xref_count": len(aggregate.xrefs),
            "pseudocode_count": len(aggregate.pseudocode),
        },
    )


def _obfuscation_document(assessments: Sequence[ObfuscationAssessment]) -> JsonObject:
    """Return JSON-safe, bounded explainable flattening assessments."""
    return cast(
        JsonObject,
        {
            "assessments": [
                {
                    "function_name": item.function_name,
                    "flattened": item.flattened,
                    "score": item.score,
                    "dispatcher_blocks": item.dispatcher_blocks,
                    "indirect_jumps": item.indirect_jumps,
                    "reason": item.reason,
                }
                for item in assessments[:16]
            ]
        },
    )


def _bounded_readable_source(
    pseudocode: Sequence[BinaryPseudocode], *, max_chars: int, total_chars: int
) -> tuple[BinaryPseudocode, ...]:
    """Select complete bounded excerpts so readability cannot exhaust output quota."""
    selected: list[BinaryPseudocode] = []
    remaining = total_chars
    for item in pseudocode[:256]:
        text = item["text"][:max_chars]
        if not text or len(text) > remaining:
            continue
        selected.append(
            BinaryPseudocode(
                function_name=item["function_name"],
                address=item["address"],
                text=text,
                tool_name=item["tool_name"],
            )
        )
        remaining -= len(text)
    return tuple(selected)


def _target_addresses(job: Job, limits: BinaryAnalysisLimits) -> tuple[int, ...]:
    arguments = job.get("arguments")
    value = arguments.get("target_addresses") if isinstance(arguments, Mapping) else None
    if value is None:
        return ()
    if not isinstance(value, list):
        raise BinaryAnalysisExecutionError(
            "binary_import.invalid_target_addresses",
            "target_addresses must be an array of non-negative integers",
        )
    items = cast(list[object], value)
    if len(items) > limits.max_symbolic_functions:
        raise BinaryAnalysisExecutionError(
            "binary_import.too_many_target_addresses",
            "target address count exceeds the configured symbolic-analysis limit",
            details={
                "target_count": len(items),
                "max_targets": limits.max_symbolic_functions,
            },
        )
    addresses: set[int] = set()
    for item in items:
        if isinstance(item, bool) or not isinstance(item, int) or item < 0:
            raise BinaryAnalysisExecutionError(
                "binary_import.invalid_target_addresses",
                "target_addresses must contain only non-negative integers",
            )
        addresses.add(item)
    return tuple(sorted(addresses))


def _validate_symbolic_targets(target_addresses: tuple[int, ...], metadata: BinaryMetadata) -> None:
    executable_ranges = [
        (
            section["virtual_address"],
            section["virtual_address"] + max(section["virtual_size"], section["file_size"]),
        )
        for section in metadata.sections
        if section["executable"]
    ]
    invalid = [
        address
        for address in target_addresses
        if not any(start <= address < end for start, end in executable_ranges)
    ]
    if invalid:
        raise BinaryAnalysisExecutionError(
            "binary_import.target_outside_executable_section",
            "symbolic-analysis targets must be inside executable sections",
            details={"invalid_addresses": invalid},
        )


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


def _copy_stream(source: IO[bytes], destination: Path) -> None:
    with destination.open("xb") as target:
        shutil.copyfileobj(source, target, length=1024 * 1024)


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
            details=cast(JsonObject, dict(details or {})),
        ),
    )
