"""Structured Sandbox Runner orchestration and CAS output publication."""

from __future__ import annotations

import asyncio
import hashlib
import io
import shutil
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePath, PurePosixPath
from typing import Any, cast

from jsonschema import Draft202012Validator
from vulnweaver_artifact_store import ArtifactStore, StoredObject
from vulnweaver_contracts import (
    FailureKind,
    JsonObject,
    SandboxOutput,
    SandboxRequest,
    SandboxResourceUsage,
    SandboxResult,
    SandboxStatus,
    SchemaVersion,
    StructuredFailure,
    validate_contract,
)
from vulnweaver_tool_runtime import ToolRegistry
from vulnweaver_tool_runtime.errors import ToolNotFound

from vulnweaver_sandbox_runner.runtime import (
    RuntimeExecution,
    RuntimeRequest,
    SandboxRuntime,
)

CommandBuilder = Callable[[Mapping[str, object], PurePath, PurePath], Sequence[str]]


@dataclass(frozen=True, slots=True)
class SandboxCommandProfile:
    """Trusted code-owned command construction for one exact ToolSpec identity."""

    tool_name: str
    tool_version: str
    image_ref: str
    image_digest: str
    build_argv: CommandBuilder


class SandboxRunnerError(RuntimeError):
    """Configuration or runtime failure that cannot be represented as a result."""


class SandboxRunner:
    """Validate structured requests, execute once, publish outputs, then clean up."""

    def __init__(
        self,
        store: ArtifactStore,
        registry: ToolRegistry,
        profiles: Sequence[SandboxCommandProfile],
        *,
        runtime: SandboxRuntime,
        root: str | Path,
        label: str = "vulnweaver.sandbox=true",
    ) -> None:
        self._store = store
        self._registry = registry
        self._profiles = {
            (profile.tool_name, profile.tool_version): profile for profile in profiles
        }
        self._runtime = runtime
        self._root = Path(root).expanduser().resolve()
        self._root.mkdir(parents=True, exist_ok=True)
        if not _safe_label(label):
            raise ValueError("sandbox label is invalid")
        self._label = label

    async def run(
        self,
        request: SandboxRequest,
        cancellation: asyncio.Event,
    ) -> SandboxResult:
        policy_error = self._validate_request(request)
        if policy_error is not None:
            return policy_error
        if cancellation.is_set():
            return _result(
                request["id"],
                SandboxStatus.CANCELLED,
                resource_usage=_usage(0, 0, 0, 0),
            )

        profile = self._profiles[(request["tool_name"], request["tool_version"])]
        container_name = _container_name(request["id"])
        work_dir = Path(tempfile.mkdtemp(prefix=f"{container_name}-", dir=self._root)).resolve()
        input_dir = work_dir / "input"
        output_dir = work_dir / "output"
        input_dir.mkdir()
        output_dir.mkdir()
        result: SandboxResult | None = None
        cancellation_error: asyncio.CancelledError | None = None
        runtime_started = False
        try:
            input_path = input_dir / "input.bin"
            try:
                await asyncio.to_thread(self._materialize_input, request["input_ref"], input_path)
                argv = tuple(
                    profile.build_argv(
                        request["arguments"],
                        PurePosixPath("/input/input.bin"),
                        PurePosixPath("/output"),
                    )
                )
                _validate_argv(argv)
            except (OSError, ValueError, RuntimeError) as error:
                result = _policy_result(
                    request["id"],
                    "sandbox.input_or_command_invalid",
                    "sandbox input materialization or trusted command construction failed",
                    _usage(0, 0, 0, 0),
                    kind=FailureKind.VALIDATION,
                    details={"exception_type": type(error).__name__},
                )
            else:
                runtime_request = RuntimeRequest(
                    container_name=container_name,
                    label=self._label,
                    image_ref=profile.image_ref,
                    image_digest=profile.image_digest,
                    argv=argv,
                    input_dir=input_dir,
                    output_dir=output_dir,
                    resource_budget=request["resource_budget"],
                    timeout_seconds=request["timeout_seconds"],
                    max_output_bytes=request["resource_budget"]["disk_bytes"],
                )
                runtime_started = True
                try:
                    execution = await self._runtime.run(runtime_request, cancellation)
                except asyncio.CancelledError as error:
                    cancellation_error = error
                    result = _result(
                        request["id"],
                        SandboxStatus.CANCELLED,
                        resource_usage=_usage(0, 0, 0, 0),
                    )
                except (OSError, TimeoutError, RuntimeError) as error:
                    result = _policy_result(
                        request["id"],
                        "sandbox.runtime_failed",
                        "sandbox runtime failed before a result was collected",
                        _usage(0, 0, 0, 0),
                        kind=FailureKind.ENVIRONMENT,
                        retryable=True,
                        details={"exception_type": type(error).__name__},
                        status=SandboxStatus.FAILED,
                    )
                else:
                    try:
                        result = await asyncio.to_thread(
                            self._publish_result,
                            request,
                            execution,
                            output_dir,
                        )
                    except (OSError, ValueError, RuntimeError) as error:
                        result = _policy_result(
                            request["id"],
                            "sandbox.output_collection_failed",
                            "sandbox output could not be safely collected",
                            _usage(
                                execution.duration_millis,
                                execution.cpu_millis,
                                execution.memory_bytes,
                                0,
                            ),
                            kind=FailureKind.ENVIRONMENT,
                            retryable=False,
                            details={"exception_type": type(error).__name__},
                            status=SandboxStatus.FAILED,
                        )
        finally:
            cleaned = True
            if runtime_started:
                try:
                    cleaned = await self._runtime.cleanup(container_name)
                except (OSError, RuntimeError):
                    cleaned = False
            if result is None:
                result = _policy_result(
                    request["id"],
                    "sandbox.runner_internal_error",
                    "sandbox runner did not produce a result",
                    _usage(0, 0, 0, 0),
                    kind=FailureKind.INTERNAL,
                )
            if not cleaned:
                result = _orphaned(result)
            shutil.rmtree(work_dir, ignore_errors=True)
        if cancellation_error is not None:
            raise cancellation_error
        return result

    async def recover_orphans(self) -> tuple[str, ...]:
        """Remove containers carrying this runner's ownership label."""

        try:
            names = await self._runtime.list_owned(self._label)
        except (OSError, RuntimeError):
            return ()
        recovered: list[str] = []
        for name in names:
            if not _safe_container_name(name):
                continue
            try:
                if await self._runtime.cleanup(name):
                    recovered.append(name)
            except (OSError, RuntimeError):
                continue
        return tuple(recovered)

    def _validate_request(self, request: SandboxRequest) -> SandboxResult | None:
        try:
            validate_contract("SandboxRequest", request)
        except (TypeError, ValueError) as error:
            return _policy_result(
                _request_id(request),
                "sandbox.request_invalid",
                "sandbox request does not satisfy the public contract",
                _usage(0, 0, 0, 0),
                details={"exception_type": type(error).__name__},
            )
        try:
            spec = self._registry.get(request["tool_name"], request["tool_version"])
        except ToolNotFound as error:
            return _policy_result(
                request["id"],
                "sandbox.tool_not_registered",
                "sandbox tool identity is not registered",
                _usage(0, 0, 0, 0),
                details={"exception_type": type(error).__name__},
            )
        profile = self._profiles.get((request["tool_name"], request["tool_version"]))
        if profile is None:
            return _policy_result(
                request["id"],
                "sandbox.command_profile_missing",
                "sandbox tool has no trusted command profile",
                _usage(0, 0, 0, 0),
            )
        if (
            request["image_digest"] != spec["image_digest"]
            or profile.image_digest != spec["image_digest"]
        ):
            return _policy_result(
                request["id"],
                "sandbox.image_identity_mismatch",
                "sandbox image digest does not match the registered ToolSpec",
                _usage(0, 0, 0, 0),
            )
        if request["artifact_kind"] not in spec["accepted_artifacts"]:
            return _policy_result(
                request["id"],
                "sandbox.artifact_kind_rejected",
                "sandbox tool does not accept this artifact kind",
                _usage(0, 0, 0, 0),
            )
        if (
            spec["network_policy"]["access"] != "none"
            or spec["network_policy"]["allowed_hosts"]
            or not spec["filesystem_policy"]["input_read_only"]
            or not spec["filesystem_policy"]["isolated_output"]
            or spec["filesystem_policy"]["allow_host_paths"]
            or spec["approval_required"]
        ):
            return _policy_result(
                request["id"],
                "sandbox.isolation_policy_rejected",
                "sandbox ToolSpec is not compatible with the mandatory isolated runtime",
                _usage(0, 0, 0, 0),
            )
        validator = cast(Any, Draft202012Validator(spec["command_schema"]))
        command_errors = sorted(
            list(validator.iter_errors(cast(Any, dict(request["arguments"])))),
            key=lambda error: list(error.path),
        )
        if command_errors:
            return _policy_result(
                request["id"],
                "sandbox.arguments_rejected",
                "sandbox arguments do not satisfy the registered command schema",
                _usage(0, 0, 0, 0),
                details={"errors": [error.message for error in command_errors[:8]]},
            )
        if not _budget_within(request["resource_budget"], spec["resource_limits"]):
            return _policy_result(
                request["id"],
                "sandbox.resource_budget_exceeded",
                "sandbox request exceeds the registered ToolSpec resource limits",
                _usage(0, 0, 0, 0),
            )
        if request["timeout_seconds"] > spec["timeout_seconds"]:
            return _policy_result(
                request["id"],
                "sandbox.timeout_exceeded",
                "sandbox request timeout exceeds the registered ToolSpec timeout",
                _usage(0, 0, 0, 0),
            )
        try:
            _validate_argv(
                tuple(
                    profile.build_argv(
                        request["arguments"],
                        PurePosixPath("/input/input.bin"),
                        PurePosixPath("/output"),
                    )
                )
            )
        except (TypeError, ValueError) as error:
            return _policy_result(
                request["id"],
                "sandbox.command_profile_invalid",
                str(error),
                _usage(0, 0, 0, 0),
            )
        return None

    def _materialize_input(self, object_ref: str, destination: Path) -> None:
        stored = self._store.verify(object_ref)
        with self._store.open(object_ref) as source, destination.open("xb") as target:
            shutil.copyfileobj(source, target, length=1024 * 1024)
        if destination.stat().st_size != stored.size_bytes:
            raise RuntimeError("materialized sandbox input size changed")

    def _publish_result(
        self,
        request: SandboxRequest,
        execution: RuntimeExecution,
        output_dir: Path,
    ) -> SandboxResult:
        approved_outputs, output_bytes = _approved_outputs(
            output_dir,
            request["output_file_names"],
        )
        stdout_bytes = len(execution.stdout)
        stderr_bytes = len(execution.stderr)
        total_output = output_bytes + stdout_bytes + stderr_bytes
        usage = _usage(
            execution.duration_millis,
            execution.cpu_millis,
            execution.memory_bytes,
            total_output,
        )
        if total_output > request["resource_budget"]["disk_bytes"]:
            return _policy_result(
                request["id"],
                "sandbox.output_limit_exceeded",
                "sandbox output exceeds the request disk budget",
                usage,
                status=SandboxStatus.FAILED,
            )
        output_refs = _store_outputs(self._store, approved_outputs)
        remaining = request["resource_budget"]["disk_bytes"] - output_bytes
        stdout_ref, _ = _store_stream(self._store, execution.stdout, remaining)
        stderr_ref, _ = _store_stream(self._store, execution.stderr, remaining - stdout_bytes)
        status = _status(execution.status)
        failure = None
        if status is SandboxStatus.FAILED:
            failure = StructuredFailure(
                code="sandbox.tool_failed",
                kind=FailureKind.TOOL,
                message="sandbox tool exited unsuccessfully",
                retryable=False,
                details={"exit_code": execution.exit_code},
            )
        elif status is SandboxStatus.TIMED_OUT:
            failure = StructuredFailure(
                code="sandbox.timeout",
                kind=FailureKind.TIMEOUT,
                message="sandbox tool exceeded its time limit",
                retryable=True,
                details={},
            )
        elif status is SandboxStatus.CANCELLED:
            failure = StructuredFailure(
                code="sandbox.cancelled",
                kind=FailureKind.CANCELLED,
                message="sandbox execution was cancelled",
                retryable=False,
                details={},
            )
        return SandboxResult(
            schema_version=SchemaVersion.VALUE_1_0_0,
            request_id=request["id"],
            status=status,
            exit_code=execution.exit_code,
            stdout_ref=stdout_ref,
            stderr_ref=stderr_ref,
            outputs=output_refs,
            resource_usage=usage,
            failure=failure,
        )


def _approved_outputs(
    output_dir: Path,
    allowed_names: list[str],
) -> tuple[tuple[Path, ...], int]:
    allowed = set(allowed_names)
    approved: dict[str, Path] = {}
    total = 0
    for path in output_dir.iterdir():
        if path.is_symlink() or not path.is_file() or path.name not in allowed:
            raise ValueError("sandbox produced an unapproved output path")
        if path.name in approved:
            raise ValueError("sandbox produced a duplicate output path")
        size = path.stat().st_size
        total += size
        approved[path.name] = path
    return tuple(approved[name] for name in sorted(approved)), total


def _store_outputs(store: ArtifactStore, paths: tuple[Path, ...]) -> list[SandboxOutput]:
    outputs: list[SandboxOutput] = []
    for path in paths:
        stored = _store_path(store, path, path.stat().st_size)
        outputs.append(
            SandboxOutput(
                path=path.name,
                object_ref=stored.object_ref,
                digest=stored.digest,
                size_bytes=stored.size_bytes,
            )
        )
    return outputs


def _store_path(store: ArtifactStore, path: Path, max_bytes: int) -> StoredObject:
    with path.open("rb") as source:
        return store.put_stream(source, max_bytes=max(1, max_bytes))


def _store_stream(store: ArtifactStore, value: bytes, max_bytes: int) -> tuple[str | None, int]:
    if not value:
        return None, 0
    stored = store.put_stream(io.BytesIO(value), max_bytes=max(1, max_bytes))
    return stored.object_ref, stored.size_bytes


def _budget_within(request: Mapping[str, object], limit: Mapping[str, object]) -> bool:
    keys = (
        "max_model_tokens",
        "cpu_millis",
        "memory_bytes",
        "disk_bytes",
        "max_tool_concurrency",
        "max_dynamic_runs",
        "timeout_seconds",
    )
    for key in keys:
        request_value = request[key]
        limit_value = limit[key]
        if not isinstance(request_value, int) or not isinstance(limit_value, int):
            return False
        if request_value > limit_value:
            return False
    return True


def _validate_argv(argv: tuple[str, ...]) -> None:
    if not argv or len(argv) > 64:
        raise ValueError("sandbox command must contain between 1 and 64 arguments")
    for argument in argv:
        if not argument or len(argument) > 4096:
            raise ValueError("sandbox command arguments must be bounded strings")
        if "\x00" in argument or "\n" in argument or "\r" in argument:
            raise ValueError("sandbox command arguments cannot contain control characters")
        if argument in {"--privileged", "--network=host", "--pid=host", "--ipc=host"}:
            raise ValueError("sandbox command cannot request container escape flags")


def _status(value: str) -> SandboxStatus:
    try:
        return SandboxStatus(value)
    except ValueError:
        return SandboxStatus.FAILED


def _request_id(request: Mapping[str, object]) -> str:
    value = request.get("id")
    return value if isinstance(value, str) and value else "sandbox:invalid-request"


def _container_name(request_id: str) -> str:
    return "vw-sbx-" + hashlib.sha256(request_id.encode("utf-8")).hexdigest()[:24]


def _safe_container_name(value: str) -> bool:
    return (
        bool(value) and len(value) <= 128 and all(char.isalnum() or char in "_-" for char in value)
    )


def _safe_label(value: str) -> bool:
    return (
        bool(value)
        and len(value) <= 256
        and all(char.isalnum() or char in "._=:/-" for char in value)
    )


def _usage(duration: int, cpu: int, memory: int, output: int) -> SandboxResourceUsage:
    return SandboxResourceUsage(
        duration_millis=max(0, duration),
        cpu_millis=max(0, cpu),
        memory_bytes=max(0, memory),
        output_bytes=max(0, output),
    )


def _result(
    request_id: str,
    status: SandboxStatus,
    *,
    resource_usage: SandboxResourceUsage,
    failure: StructuredFailure | None = None,
) -> SandboxResult:
    return SandboxResult(
        schema_version=SchemaVersion.VALUE_1_0_0,
        request_id=request_id,
        status=status,
        exit_code=None,
        stdout_ref=None,
        stderr_ref=None,
        outputs=[],
        resource_usage=resource_usage,
        failure=failure,
    )


def _policy_result(
    request_id: str,
    code: str,
    message: str,
    usage: SandboxResourceUsage,
    *,
    kind: FailureKind = FailureKind.POLICY,
    retryable: bool = False,
    details: Mapping[str, object] | None = None,
    status: SandboxStatus = SandboxStatus.POLICY_DENIED,
) -> SandboxResult:
    return _result(
        request_id,
        status,
        resource_usage=usage,
        failure=StructuredFailure(
            code=code,
            kind=kind,
            message=message,
            retryable=retryable,
            details=cast(JsonObject, dict(details or {})),
        ),
    )


def _orphaned(result: SandboxResult) -> SandboxResult:
    return SandboxResult(
        schema_version=SchemaVersion.VALUE_1_0_0,
        request_id=result["request_id"],
        status=SandboxStatus.ORPHANED,
        exit_code=result["exit_code"],
        stdout_ref=result["stdout_ref"],
        stderr_ref=result["stderr_ref"],
        outputs=result["outputs"],
        resource_usage=result["resource_usage"],
        failure=StructuredFailure(
            code="sandbox.cleanup_failed",
            kind=FailureKind.ENVIRONMENT,
            message="sandbox container cleanup could not be confirmed",
            retryable=True,
            details={},
        ),
    )
