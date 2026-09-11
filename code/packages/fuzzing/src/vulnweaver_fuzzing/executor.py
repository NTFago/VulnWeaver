"""Policy-bound fuzz execution through Sandbox Runner and CAS triage."""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import re
import tarfile
import tempfile
from collections.abc import Callable, Mapping, Sequence
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import BinaryIO, Protocol, cast

from vulnweaver_artifact_store import ArtifactStore, ArtifactStoreError, StoredObject
from vulnweaver_contracts import (
    ArtifactKind,
    CrashManifest,
    CrashManifestEntry,
    CrashRecord,
    FailureKind,
    FuzzRequest,
    FuzzResult,
    FuzzStatus,
    FuzzToolSummary,
    JsonObject,
    SandboxRequest,
    SandboxResult,
    SandboxStatus,
    StructuredFailure,
    ToolIdentity,
    ToolSpec,
    validate_contract,
)
from vulnweaver_tool_runtime import (
    ToolRegistry,
    ToolRuntimeError,
)

from vulnweaver_fuzzing.profiles import (
    AFL_CASR_OUTPUT_NAMES,
    AFL_CASR_PROFILE,
    AFL_CASR_TOOL_NAME,
    AFL_CASR_TOOL_VERSION,
    CASR_TOOL_NAME,
    CASR_TOOL_VERSION,
)
from vulnweaver_fuzzing.triage import (
    CrashTriageError,
    CrashTriageService,
    validate_fuzz_request,
)

_BUNDLE_VERSION = "1"
_BUNDLE_MANIFEST_NAME = "vulnweaver-bundle.json"
_TARGET_NAME = "target"
_SEED_PREFIX = "seeds/"
_SAFE_MEMBER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$")
_DEFAULT_MAX_BUNDLE_BYTES = 256 * 1024 * 1024
_DEFAULT_MAX_MINIMIZED_INPUT_BYTES = 16 * 1024 * 1024
_DEFAULT_MAX_MINIMIZED_INPUT_TOTAL_BYTES = 256 * 1024 * 1024


class FuzzSandbox(Protocol):
    async def run(self, request: SandboxRequest, cancellation: asyncio.Event) -> SandboxResult: ...


@dataclass(frozen=True, slots=True)
class FuzzRunOutcome:
    result: FuzzResult
    crashes: tuple[CrashRecord, ...]


def build_fuzz_input_bundle(
    store: ArtifactStore,
    target_ref: str,
    seed_refs: Sequence[str],
    *,
    max_bytes: int = _DEFAULT_MAX_BUNDLE_BYTES,
) -> StoredObject:
    """Create a deterministic, immutable target/seed bundle for one fuzz run."""

    if max_bytes < 1:
        raise ValueError("fuzz bundle size limit must be positive")
    if not seed_refs:
        raise CrashTriageError("fuzz input bundle needs at least one seed")
    refs = (target_ref, *seed_refs)
    stored = [store.verify(object_ref) for object_ref in refs]
    manifest = {
        "version": _BUNDLE_VERSION,
        "target": {"name": _TARGET_NAME, "object_ref": target_ref},
        "seeds": [
            {"name": f"{_SEED_PREFIX}{index:04d}", "object_ref": object_ref}
            for index, object_ref in enumerate(seed_refs)
        ],
    }
    manifest_bytes = _json_bytes(manifest)
    estimated_size = len(manifest_bytes) + sum(item.size_bytes for item in stored)
    estimated_size += 512 * (2 + len(seed_refs)) + 1024
    if estimated_size > max_bytes:
        raise CrashTriageError("fuzz input bundle exceeds its configured size limit")

    with tempfile.TemporaryFile(mode="w+b") as bundle:
        with tarfile.open(fileobj=bundle, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            _add_tar_bytes(archive, _BUNDLE_MANIFEST_NAME, manifest_bytes)
            _add_tar_object(archive, store, _TARGET_NAME, target_ref, stored[0].size_bytes)
            for index, object_ref in enumerate(seed_refs, start=1):
                _add_tar_object(
                    archive,
                    store,
                    f"{_SEED_PREFIX}{index - 1:04d}",
                    object_ref,
                    stored[index].size_bytes,
                )
        bundle.seek(0)
        return store.put_stream(bundle, max_bytes=max_bytes)


class FuzzExecutionService:
    """Run one bounded fuzz request and normalize only CAS-published outputs."""

    def __init__(
        self,
        store: ArtifactStore,
        registry: ToolRegistry,
        sandbox: FuzzSandbox,
        *,
        fuzz_tool: ToolIdentity,
        crash_tool: ToolIdentity,
        now: Callable[[], datetime] | None = None,
        max_bundle_bytes: int = _DEFAULT_MAX_BUNDLE_BYTES,
        max_minimized_input_bytes: int = _DEFAULT_MAX_MINIMIZED_INPUT_BYTES,
        max_minimized_input_total_bytes: int = _DEFAULT_MAX_MINIMIZED_INPUT_TOTAL_BYTES,
    ) -> None:
        if (
            max_bundle_bytes < 1
            or max_minimized_input_bytes < 1
            or max_minimized_input_total_bytes < 1
        ):
            raise ValueError("fuzz artifact limits must be positive")
        self._store = store
        self._registry = registry
        self._sandbox = sandbox
        self._fuzz_tool = fuzz_tool
        self._crash_tool = crash_tool
        self._now = now or (lambda: datetime.now(UTC))
        self._max_bundle_bytes = max_bundle_bytes
        self._max_minimized_input_bytes = max_minimized_input_bytes
        self._max_minimized_input_total_bytes = max_minimized_input_total_bytes

    async def run(self, request: FuzzRequest, cancellation: asyncio.Event) -> FuzzResult:
        return (await self.run_with_crashes(request, cancellation)).result

    async def run_with_crashes(
        self, request: FuzzRequest, cancellation: asyncio.Event
    ) -> FuzzRunOutcome:
        limits = validate_fuzz_request(request)
        triage = CrashTriageService(limits)
        try:
            spec = self._validate_tool_identity()
            bundle = build_fuzz_input_bundle(
                self._store,
                request["sandbox_request"]["input_ref"],
                request["seed_refs"],
                max_bytes=self._max_bundle_bytes,
            )
            sandbox_request = self._sandbox_request(request, spec, bundle.object_ref)
            sandbox_result = await self._sandbox.run(sandbox_request, cancellation)
        except asyncio.CancelledError:
            raise
        except Exception as error:
            return FuzzRunOutcome(triage.build_result(
                request["job_id"],
                status=FuzzStatus.FAILED,
                coverage_percent=None,
                created_at=_timestamp(self._now()),
                failure=_failure_for_exception(error, phase="execution"),
            ), ())

        # The status may arrive as the enum or as its raw value from HTTP.
        if SandboxStatus(sandbox_result["status"]) is not SandboxStatus.SUCCEEDED:
            status = _fuzz_status(sandbox_result["status"])
            failure = sandbox_result["failure"] or _failure(
                "fuzz.sandbox_failed",
                FailureKind.ENVIRONMENT,
                "fuzz Sandbox Runner did not complete successfully",
            )
            return FuzzRunOutcome(triage.build_result(
                request["job_id"],
                status=status,
                coverage_percent=None,
                created_at=_timestamp(self._now()),
                failure=failure,
            ), ())

        try:
            summary = cast(
                FuzzToolSummary,
                _read_output(
                    self._store, sandbox_result, "fuzz-summary.json", "FuzzToolSummary", 64 * 1024
                ),
            )
            manifest = cast(
                CrashManifest,
                _read_output(
                    self._store,
                    sandbox_result,
                    "crash-manifest.json",
                    "CrashManifest",
                    4 * 1024 * 1024,
                ),
            )
            input_refs = _publish_minimized_inputs(
                self._store,
                sandbox_result,
                manifest,
                max_bytes=self._max_minimized_input_bytes,
                max_total_bytes=min(
                    self._max_minimized_input_total_bytes,
                    request["sandbox_request"]["resource_budget"]["disk_bytes"],
                ),
                max_archive_bytes=request["sandbox_request"]["resource_budget"]["disk_bytes"],
                max_entries=limits.max_crashes,
            )
            selected_crashes = manifest["crashes"][: limits.max_crashes]
            entries: list[Mapping[str, object]] = [
                _triage_entry(entry, input_refs[entry["input_path"]]) for entry in selected_crashes
            ]
            triage.ingest_many(
                entries,
                artifact_version_id=request["artifact_version_id"],
                fuzz_tool=self._fuzz_tool,
                tool=self._crash_tool,
                created_at=_timestamp(self._now()),
            )
            triage.set_execution_count(summary["executions"])
            partial = len(manifest["crashes"]) > limits.max_crashes
            return FuzzRunOutcome(triage.build_result(
                request["job_id"],
                status=FuzzStatus.PARTIAL if partial else FuzzStatus.SUCCEEDED,
                coverage_percent=summary["coverage_percent"],
                created_at=_timestamp(self._now()),
                failure=(
                    _failure(
                        "fuzz.crash_budget_exceeded",
                        FailureKind.TOOL,
                        "fuzz tool reported more crashes than the configured result budget",
                    )
                    if partial
                    else None
                ),
            ), triage.records())
        except asyncio.CancelledError:
            raise
        except Exception as error:
            return FuzzRunOutcome(triage.build_result(
                request["job_id"],
                status=FuzzStatus.FAILED,
                coverage_percent=None,
                created_at=_timestamp(self._now()),
                failure=_failure_for_exception(error, phase="normalization"),
            ), triage.records())

    def _validate_tool_identity(self) -> ToolSpec:
        try:
            spec = self._registry.get(AFL_CASR_TOOL_NAME, AFL_CASR_TOOL_VERSION)
            validate_contract("ToolIdentity", self._fuzz_tool)
            validate_contract("ToolIdentity", self._crash_tool)
        except (KeyError, TypeError, ValueError) as error:
            raise CrashTriageError("AFL++/CASR ToolSpec or tool identity is invalid") from error
        if (
            self._fuzz_tool["name"] != spec["name"]
            or self._fuzz_tool["version"] != spec["version"]
            or self._fuzz_tool.get("image_digest") != spec["image_digest"]
            or self._crash_tool["name"] != CASR_TOOL_NAME
            or self._crash_tool["version"] != CASR_TOOL_VERSION
            or self._crash_tool.get("image_digest") != spec["image_digest"]
        ):
            raise CrashTriageError("fuzz or CASR tool identity is not pinned to the profile")
        return spec

    def _sandbox_request(
        self, request: FuzzRequest, spec: ToolSpec, bundle_ref: str
    ) -> SandboxRequest:
        original = request["sandbox_request"]
        arguments: JsonObject = {
            "profile": AFL_CASR_PROFILE,
            "max_executions": request["max_executions"],
            "max_duration_seconds": request["max_duration_seconds"],
            "max_crashes": request["max_crashes"],
            "collect_coverage": request["collect_coverage"],
        }
        budget = original["resource_budget"]
        return cast(
            SandboxRequest,
            {
                **original,
                "tool_name": spec["name"],
                "tool_version": spec["version"],
                "image_digest": spec["image_digest"],
                "artifact_kind": ArtifactKind.DERIVED,
                "input_ref": bundle_ref,
                "arguments": arguments,
                "output_file_names": list(AFL_CASR_OUTPUT_NAMES),
                "resource_budget": budget,
                "timeout_seconds": original["timeout_seconds"],
            },
        )


def _add_tar_bytes(archive: tarfile.TarFile, name: str, value: bytes) -> None:
    info = _tar_info(name, len(value))
    archive.addfile(info, io.BytesIO(value))


def _add_tar_object(
    archive: tarfile.TarFile,
    store: ArtifactStore,
    name: str,
    object_ref: str,
    size_bytes: int,
) -> None:
    info = _tar_info(name, size_bytes)
    with store.open(object_ref) as source:
        archive.addfile(info, source)


def _tar_info(name: str, size_bytes: int) -> tarfile.TarInfo:
    if not _safe_member(name):
        raise CrashTriageError("fuzz bundle contains an unsafe member name")
    info = tarfile.TarInfo(name)
    info.size = size_bytes
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    info.mode = 0o600
    info.uname = ""
    info.gname = ""
    return info


def _read_output(
    store: ArtifactStore,
    result: SandboxResult,
    name: str,
    definition: str,
    max_bytes: int,
) -> Mapping[str, object]:
    matches = [item for item in result["outputs"] if item["path"] == name]
    if len(matches) != 1:
        raise CrashTriageError(f"Sandbox output {name!r} is missing or duplicated")
    output = matches[0]
    stored = store.verify(output["object_ref"])
    if stored.digest != output["digest"] or stored.size_bytes != output["size_bytes"]:
        raise CrashTriageError(f"Sandbox output {name!r} has inconsistent CAS metadata")
    if stored.size_bytes > max_bytes:
        raise CrashTriageError(f"Sandbox output {name!r} exceeds its parser limit")
    try:
        with store.open(output["object_ref"]) as source:
            raw = json.loads(
                source.read().decode("utf-8"),
                parse_constant=_reject_json_constant,
            )
    except (OSError, UnicodeDecodeError, ValueError) as error:
        raise CrashTriageError(f"Sandbox output {name!r} is not valid JSON") from error
    if not isinstance(raw, Mapping):
        raise CrashTriageError(f"Sandbox output {name!r} must be a JSON object")
    payload = cast(Mapping[str, object], raw)
    try:
        validate_contract(definition, payload)
    except (TypeError, ValueError) as error:
        raise CrashTriageError(f"Sandbox output {name!r} violates {definition}") from error
    return payload


def _publish_minimized_inputs(
    store: ArtifactStore,
    result: SandboxResult,
    manifest: CrashManifest,
    *,
    max_bytes: int,
    max_total_bytes: int,
    max_archive_bytes: int,
    max_entries: int,
) -> dict[str, str]:
    matches = [item for item in result["outputs"] if item["path"] == "minimized-inputs.tar"]
    if len(matches) != 1:
        raise CrashTriageError("minimized input archive is missing or duplicated")
    expected = {entry["input_path"] for entry in manifest["crashes"]}
    expected_digests = {entry["input_path"]: entry["input_digest"] for entry in manifest["crashes"]}
    selected = {entry["input_path"] for entry in manifest["crashes"][:max_entries]}
    if len(expected) != len(manifest["crashes"]):
        raise CrashTriageError("crash manifest contains duplicate input paths")
    stored = store.verify(matches[0]["object_ref"])
    if stored.digest != matches[0]["digest"] or stored.size_bytes != matches[0]["size_bytes"]:
        raise CrashTriageError("minimized input archive has inconsistent CAS metadata")
    if stored.size_bytes > max_archive_bytes:
        raise CrashTriageError("minimized input archive exceeds its parser budget")
    seen: set[str] = set()
    selected_bytes = 0
    try:
        with (
            store.open(matches[0]["object_ref"]) as source,
            closing(tarfile.open(fileobj=source, mode="r:")) as archive,
        ):
            for member in archive:
                if not member.isreg() or not _safe_member(member.name):
                    raise CrashTriageError("minimized input archive contains an unsafe member")
                if member.name not in expected or member.name in seen:
                    raise CrashTriageError("minimized input archive contains an unexpected member")
                seen.add(member.name)
                if member.size > max_bytes:
                    raise CrashTriageError("minimized input exceeds its per-input budget")
                if member.name not in selected:
                    continue
                selected_bytes += member.size
                if selected_bytes > max_total_bytes:
                    raise CrashTriageError("minimized inputs exceed their cumulative budget")
                extracted = archive.extractfile(member)
                if (
                    extracted is None
                    or _stream_digest(cast(BinaryIO, extracted)) != expected_digests[member.name]
                ):
                    raise CrashTriageError(
                        "minimized input digest does not match the crash manifest"
                    )
    except CrashTriageError:
        raise
    except (OSError, tarfile.TarError, ValueError) as error:
        raise CrashTriageError("minimized input archive could not be parsed") from error
    if seen != expected:
        raise CrashTriageError("minimized input archive does not cover the crash manifest")

    refs: dict[str, str] = {}
    try:
        with (
            store.open(matches[0]["object_ref"]) as source,
            closing(tarfile.open(fileobj=source, mode="r:")) as archive,
        ):
            for member in archive:
                if member.name not in selected:
                    continue
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise CrashTriageError("minimized input archive member cannot be read")
                published = store.put_stream(cast(BinaryIO, extracted), max_bytes=max_bytes)
                if published.digest != expected_digests[member.name]:
                    raise CrashTriageError(
                        "published minimized input digest changed after validation"
                    )
                refs[member.name] = published.object_ref
    except CrashTriageError:
        raise
    except (OSError, tarfile.TarError, ValueError) as error:
        raise CrashTriageError("minimized input archive could not be published") from error
    if set(refs) != selected:
        raise CrashTriageError("minimized input archive does not cover the selected crashes")
    return refs


def _stream_digest(source: BinaryIO) -> str:
    digest = hashlib.sha256()
    while chunk := source.read(64 * 1024):
        digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _triage_entry(entry: CrashManifestEntry, input_ref: str) -> dict[str, object]:
    return {
        "input_ref": input_ref,
        "input_digest": entry["input_digest"],
        "signal": entry["signal"],
        "exit_code": entry["exit_code"],
        "stack_frames": entry["stack_frames"],
    }


def _fuzz_status(status: SandboxStatus) -> FuzzStatus:
    if status is SandboxStatus.TIMED_OUT:
        return FuzzStatus.TIMED_OUT
    if status is SandboxStatus.CANCELLED:
        return FuzzStatus.CANCELLED
    return FuzzStatus.FAILED


def _failure_for_exception(error: Exception, *, phase: str) -> StructuredFailure:
    if isinstance(error, ArtifactStoreError):
        return _failure(
            f"fuzz.{error.code}",
            FailureKind.DEPENDENCY,
            "fuzz artifact storage failed",
            retryable=error.retryable,
            details={"exception_type": type(error).__name__, **error.details},
        )
    if isinstance(error, ToolRuntimeError):
        return _failure(
            f"fuzz.{error.code}",
            FailureKind.POLICY,
            "fuzz tool registration or policy validation failed",
            details={"exception_type": type(error).__name__, **error.details},
        )
    if isinstance(error, CrashTriageError):
        return _failure(
            "fuzz.result_invalid" if phase == "normalization" else "fuzz.request_invalid",
            FailureKind.TOOL if phase == "normalization" else FailureKind.VALIDATION,
            (
                "fuzz tool output failed contract, archive, or CAS integrity checks"
                if phase == "normalization"
                else "fuzz request, bundle, or tool identity is invalid"
            ),
            details={"exception_type": type(error).__name__},
        )
    if isinstance(error, (OSError, TimeoutError, RuntimeError)):
        return _failure(
            "fuzz.execution_failed",
            FailureKind.ENVIRONMENT,
            f"fuzz {phase} failed because its runtime environment was unavailable",
            retryable=True,
            details={"exception_type": type(error).__name__},
        )
    return _failure(
        "fuzz.internal_error",
        FailureKind.INTERNAL,
        f"fuzz {phase} failed unexpectedly",
        details={"exception_type": type(error).__name__},
    )


def _failure(
    code: str,
    kind: FailureKind,
    message: str,
    *,
    retryable: bool = False,
    details: Mapping[str, object] | None = None,
) -> StructuredFailure:
    return cast(
        StructuredFailure,
        {
            "code": code,
            "kind": kind,
            "message": message,
            "retryable": retryable,
            "details": dict(details or {}),
        },
    )


def _json_bytes(value: Mapping[str, object]) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant {value}")


def _safe_member(name: str) -> bool:
    return bool(_SAFE_MEMBER.fullmatch(name)) or (
        name.startswith(_SEED_PREFIX) and bool(_SAFE_MEMBER.fullmatch(name[len(_SEED_PREFIX) :]))
    )


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("fuzz execution clock must be timezone-aware")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
