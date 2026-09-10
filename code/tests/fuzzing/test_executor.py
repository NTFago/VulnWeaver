from __future__ import annotations

import asyncio
import hashlib
import io
import json
import tarfile
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import cast

import pytest
from vulnweaver_artifact_store import (
    ArtifactNotFound,
    ArtifactStoreIOError,
    LocalContentAddressedStore,
    StoredObject,
)
from vulnweaver_contracts import (
    ArtifactKind,
    FuzzRequest,
    ResourceBudget,
    SandboxResult,
    SandboxStatus,
    SchemaVersion,
    ToolIdentity,
    ToolSpec,
)
from vulnweaver_fuzzing import (
    FuzzExecutionService,
    afl_casr_command_profile,
    afl_casr_tool_spec,
    build_fuzz_input_bundle,
)
from vulnweaver_tool_runtime import ToolRegistry

IMAGE_DIGEST = "sha256:" + "a" * 64
FUZZ_TOOL = cast(
    ToolIdentity,
    {"name": "afl-casr", "version": "1.0.0", "image_digest": IMAGE_DIGEST},
)
CASR_TOOL = cast(
    ToolIdentity,
    {"name": "casr", "version": "2.12.0", "image_digest": IMAGE_DIGEST},
)


def budget(**overrides: int) -> ResourceBudget:
    value: dict[str, int] = {
        "max_model_tokens": 0,
        "cpu_millis": 1000,
        "memory_bytes": 16 * 1024 * 1024,
        "disk_bytes": 4 * 1024 * 1024,
        "max_tool_concurrency": 1,
        "max_dynamic_runs": 1,
        "timeout_seconds": 30,
    }
    value.update(overrides)
    return cast(ResourceBudget, value)


def spec() -> ToolSpec:
    return afl_casr_tool_spec(IMAGE_DIGEST, budget())


def request(target_ref: str, seed_ref: str) -> FuzzRequest:
    return cast(
        FuzzRequest,
        {
            "schema_version": "1.0.0",
            "id": "fuzz-request:executor",
            "job_id": "job:fuzz-executor",
            "sandbox_request": {
                "schema_version": "1.0.0",
                "id": "sandbox-request:executor",
                "tool_name": "placeholder",
                "tool_version": "0.0.0",
                "image_digest": IMAGE_DIGEST,
                "artifact_kind": ArtifactKind.ELF,
                "input_ref": target_ref,
                "arguments": {"profile": "caller-input-is-replaced"},
                "output_file_names": ["caller-output-is-replaced"],
                "resource_budget": budget(),
                "timeout_seconds": 30,
            },
            "artifact_version_id": "artifact-version:fuzz-executor",
            "seed_refs": [seed_ref],
            "max_executions": 10,
            "max_duration_seconds": 30,
            "max_crashes": 4,
            "collect_coverage": True,
        },
    )


class _FakeSandbox:
    def __init__(self, result: SandboxResult) -> None:
        self.result = result
        self.requests = []

    async def run(self, request: object, cancellation: asyncio.Event) -> SandboxResult:
        del cancellation
        self.requests.append(request)
        return self.result


def _output(store: LocalContentAddressedStore, name: str, value: bytes) -> dict[str, object]:
    stored = store.put_stream(io.BytesIO(value), max_bytes=8 * 1024 * 1024)
    return {
        "path": name,
        "object_ref": stored.object_ref,
        "digest": stored.digest,
        "size_bytes": stored.size_bytes,
    }


def _minimized_tar(value: bytes, name: str = "crash-0001") -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        info = tarfile.TarInfo(name)
        info.size = len(value)
        info.mtime = 0
        archive.addfile(info, io.BytesIO(value))
    return output.getvalue()


def _sandbox_result(store: LocalContentAddressedStore, minimized: bytes) -> SandboxResult:
    minimized_digest = "sha256:" + hashlib.sha256(minimized).hexdigest()
    manifest = json.dumps(
        {
            "schema_version": "1.0.0",
            "crashes": [
                {
                    "input_path": "crash-0001",
                    "input_digest": minimized_digest,
                    "signal": "SIGSEGV",
                    "exit_code": -11,
                    "stack_frames": ["#0 0x401000 in parse", "#1 0x402000 in main"],
                }
            ],
        }
    ).encode()
    summary = json.dumps(
        {"schema_version": "1.0.0", "executions": 3, "coverage_percent": 12.5}
    ).encode()
    return cast(
        SandboxResult,
        {
            "schema_version": SchemaVersion.VALUE_1_0_0,
            "request_id": "sandbox-request:executor",
            "status": SandboxStatus.SUCCEEDED,
            "exit_code": 0,
            "stdout_ref": None,
            "stderr_ref": None,
            "outputs": [
                _output(store, "fuzz-summary.json", summary),
                _output(store, "crash-manifest.json", manifest),
                _output(store, "minimized-inputs.tar", _minimized_tar(minimized)),
            ],
            "resource_usage": {
                "duration_millis": 10,
                "cpu_millis": 5,
                "memory_bytes": 1024,
                "output_bytes": len(summary) + len(manifest) + len(minimized),
            },
            "failure": None,
        },
    )


def _sandbox_result_for_crashes(
    store: LocalContentAddressedStore,
    values: list[bytes],
    *,
    archive_mode: str = "w",
) -> SandboxResult:
    result = _sandbox_result(store, values[0])
    manifest = json.dumps(
        {
            "schema_version": "1.0.0",
            "crashes": [
                {
                    "input_path": f"crash-{index:04d}",
                    "input_digest": "sha256:" + hashlib.sha256(value).hexdigest(),
                    "signal": "SIGSEGV",
                    "exit_code": -11,
                    "stack_frames": [f"#0 0x401{index:03x} in parse"],
                }
                for index, value in enumerate(values, start=1)
            ],
        }
    ).encode()
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode=archive_mode) as tar:
        for index, value in enumerate(values, start=1):
            info = tarfile.TarInfo(f"crash-{index:04d}")
            info.size = len(value)
            info.mtime = 0
            tar.addfile(info, io.BytesIO(value))
    outputs = [
        item
        if item["path"] not in {"crash-manifest.json", "minimized-inputs.tar"}
        else _output(
            store,
            item["path"],
            manifest if item["path"] == "crash-manifest.json" else archive.getvalue(),
        )
        for item in result["outputs"]
    ]
    return cast(SandboxResult, {**result, "outputs": outputs})


def test_input_bundle_is_deterministic_and_binds_target_and_seeds(tmp_path: Path) -> None:
    store = LocalContentAddressedStore(tmp_path / "cas")
    target = store.put_stream(io.BytesIO(b"target"), max_bytes=1024)
    seed = store.put_stream(io.BytesIO(b"seed"), max_bytes=1024)

    first = build_fuzz_input_bundle(store, target.object_ref, [seed.object_ref])
    second = build_fuzz_input_bundle(store, target.object_ref, [seed.object_ref])

    assert first.object_ref == second.object_ref
    with store.open(first.object_ref) as source, tarfile.open(fileobj=source, mode="r:") as archive:
        assert archive.getnames() == [
            "vulnweaver-bundle.json",
            "target",
            "seeds/0000",
        ]


def test_executor_replaces_caller_arguments_and_publishes_crash_input(
    tmp_path: Path,
) -> None:
    store = LocalContentAddressedStore(tmp_path / "cas")
    target = store.put_stream(io.BytesIO(b"target"), max_bytes=1024)
    seed = store.put_stream(io.BytesIO(b"seed"), max_bytes=1024)
    minimized = b"crashing input"
    sandbox = _FakeSandbox(_sandbox_result(store, minimized))
    registry = ToolRegistry([spec()])
    service = FuzzExecutionService(
        store,
        registry,
        sandbox,
        fuzz_tool=FUZZ_TOOL,
        crash_tool=CASR_TOOL,
        now=lambda: datetime(2026, 9, 9, 8, 0, tzinfo=UTC),
    )

    result = asyncio.run(service.run(request(target.object_ref, seed.object_ref), asyncio.Event()))

    assert result["status"] == "succeeded"
    assert result["executions"] == 3
    assert result["coverage_percent"] == 12.5
    assert len(result["crash_ids"]) == 1
    sandbox_request = sandbox.requests[0]
    assert sandbox_request["artifact_kind"] is ArtifactKind.DERIVED
    assert sandbox_request["tool_name"] == "afl-casr"
    assert sandbox_request["arguments"]["profile"] == "afl-qemu-casr"
    assert sandbox_request["output_file_names"] == [
        "crash-manifest.json",
        "fuzz-summary.json",
        "minimized-inputs.tar",
    ]


def test_sandbox_request_budget_is_clamped_to_the_tool_spec(tmp_path: Path) -> None:
    """The Runner refuses a budget above the spec, so the executor must clamp it first."""

    store = LocalContentAddressedStore(tmp_path / "cas")
    target = store.put_stream(io.BytesIO(b"target"), max_bytes=1024)
    seed = store.put_stream(io.BytesIO(b"seed"), max_bytes=1024)
    sandbox = _FakeSandbox(_sandbox_result(store, b"crashing input"))
    registry = ToolRegistry([spec()])
    service = FuzzExecutionService(
        store,
        registry,
        sandbox,
        fuzz_tool=FUZZ_TOOL,
        crash_tool=CASR_TOOL,
        now=lambda: datetime(2026, 9, 9, 8, 0, tzinfo=UTC),
    )
    oversized = request(target.object_ref, seed.object_ref)
    oversized["sandbox_request"]["resource_budget"] = budget(
        cpu_millis=8000,
        memory_bytes=3 * 1024**3,
        disk_bytes=10 * 1024**3,
        timeout_seconds=3600,
    )

    asyncio.run(service.run(oversized, asyncio.Event()))

    limits = spec()["resource_limits"]
    request_budget = sandbox.requests[0]["resource_budget"]
    for key in ("cpu_millis", "memory_bytes", "disk_bytes", "timeout_seconds"):
        assert request_budget[key] == limits[key]
    assert sandbox.requests[0]["timeout_seconds"] <= limits["timeout_seconds"]


def test_executor_returns_structured_failure_for_digest_mismatch(tmp_path: Path) -> None:
    store = LocalContentAddressedStore(tmp_path / "cas")
    target = store.put_stream(io.BytesIO(b"target"), max_bytes=1024)
    seed = store.put_stream(io.BytesIO(b"seed"), max_bytes=1024)
    minimized = b"crashing input"
    valid = _sandbox_result(store, minimized)
    invalid_manifest = json.dumps(
        {
            "schema_version": "1.0.0",
            "crashes": [
                {
                    "input_path": "crash-0001",
                    "input_digest": "sha256:" + "c" * 64,
                    "signal": "SIGSEGV",
                    "exit_code": -11,
                    "stack_frames": ["#0 0x401000 in parse"],
                }
            ],
        }
    ).encode()
    outputs = [
        item
        if item["path"] != "crash-manifest.json"
        else _output(store, "crash-manifest.json", invalid_manifest)
        for item in valid["outputs"]
    ]
    sandbox = _FakeSandbox(cast(SandboxResult, {**valid, "outputs": outputs}))
    service = FuzzExecutionService(
        store,
        ToolRegistry([spec()]),
        sandbox,
        fuzz_tool=FUZZ_TOOL,
        crash_tool=CASR_TOOL,
    )

    result = asyncio.run(service.run(request(target.object_ref, seed.object_ref), asyncio.Event()))

    assert result["status"] == "failed"
    assert result["failure"] is not None
    assert result["failure"]["code"] == "fuzz.result_invalid"


def test_executor_marks_crash_budget_overflow_as_partial(tmp_path: Path) -> None:
    store = LocalContentAddressedStore(tmp_path / "cas")
    target = store.put_stream(io.BytesIO(b"target"), max_bytes=1024)
    seed = store.put_stream(io.BytesIO(b"seed"), max_bytes=1024)
    minimized_values = [f"crashing input {i}".encode() for i in range(1, 6)]
    sandbox = _FakeSandbox(_sandbox_result_for_crashes(store, minimized_values))
    service = FuzzExecutionService(
        store,
        ToolRegistry([spec()]),
        sandbox,
        fuzz_tool=FUZZ_TOOL,
        crash_tool=CASR_TOOL,
    )
    fuzz_request = cast(
        FuzzRequest,
        {**request(target.object_ref, seed.object_ref), "max_crashes": 2},
    )

    result = asyncio.run(service.run(fuzz_request, asyncio.Event()))

    assert result["status"] == "partial"
    assert result["failure"] is not None
    assert result["failure"]["code"] == "fuzz.crash_budget_exceeded"
    assert len(result["crash_ids"]) == 2
    for value in minimized_values[2:]:
        object_ref = "cas://sha256/" + hashlib.sha256(value).hexdigest()
        with pytest.raises(ArtifactNotFound):
            store.verify(object_ref)


def test_executor_rejects_compressed_minimized_input_archives(tmp_path: Path) -> None:
    store = LocalContentAddressedStore(tmp_path / "cas")
    target = store.put_stream(io.BytesIO(b"target"), max_bytes=1024)
    seed = store.put_stream(io.BytesIO(b"seed"), max_bytes=1024)
    sandbox = _FakeSandbox(
        _sandbox_result_for_crashes(store, [b"crashing input"], archive_mode="w:gz")
    )
    service = FuzzExecutionService(
        store,
        ToolRegistry([spec()]),
        sandbox,
        fuzz_tool=FUZZ_TOOL,
        crash_tool=CASR_TOOL,
    )

    result = asyncio.run(service.run(request(target.object_ref, seed.object_ref), asyncio.Event()))

    assert result["status"] == "failed"
    assert result["failure"] is not None
    assert result["failure"]["code"] == "fuzz.result_invalid"


def test_executor_validates_cumulative_input_budget_before_cas_publication(
    tmp_path: Path,
) -> None:
    store = LocalContentAddressedStore(tmp_path / "cas")
    target = store.put_stream(io.BytesIO(b"target"), max_bytes=1024)
    seed = store.put_stream(io.BytesIO(b"seed"), max_bytes=1024)
    minimized_values = [b"first crash", b"second crash"]
    sandbox = _FakeSandbox(_sandbox_result_for_crashes(store, minimized_values))
    service = FuzzExecutionService(
        store,
        ToolRegistry([spec()]),
        sandbox,
        fuzz_tool=FUZZ_TOOL,
        crash_tool=CASR_TOOL,
        max_minimized_input_total_bytes=len(minimized_values[0]),
    )

    result = asyncio.run(service.run(request(target.object_ref, seed.object_ref), asyncio.Event()))

    assert result["status"] == "failed"
    assert result["failure"] is not None
    assert result["failure"]["code"] == "fuzz.result_invalid"
    for value in minimized_values:
        object_ref = "cas://sha256/" + hashlib.sha256(value).hexdigest()
        with pytest.raises(ArtifactNotFound):
            store.verify(object_ref)


def test_executor_preserves_retryable_artifact_store_failures(tmp_path: Path) -> None:
    class UnavailableStore(LocalContentAddressedStore):
        def verify(self, object_ref: str) -> StoredObject:
            del object_ref
            raise ArtifactStoreIOError("artifact backend unavailable", details={"errno": 5})

    store = UnavailableStore(tmp_path / "cas")
    sandbox = _FakeSandbox(cast(SandboxResult, {}))
    service = FuzzExecutionService(
        store,
        ToolRegistry([spec()]),
        sandbox,
        fuzz_tool=FUZZ_TOOL,
        crash_tool=CASR_TOOL,
    )
    target_ref = "cas://sha256/" + "b" * 64
    seed_ref = "cas://sha256/" + "c" * 64

    result = asyncio.run(service.run(request(target_ref, seed_ref), asyncio.Event()))

    assert result["status"] == "failed"
    assert result["failure"] is not None
    assert result["failure"]["code"] == "fuzz.artifact_store_io_error"
    assert result["failure"]["kind"] == "dependency"
    assert result["failure"]["retryable"] is True


def test_profile_builds_fixed_argv_and_rejects_wrong_profile() -> None:
    profile = afl_casr_command_profile("registry.example/fuzz", IMAGE_DIGEST)
    argv = profile.build_argv(
        {
            "profile": "afl-qemu-casr",
            "max_executions": 10,
            "max_duration_seconds": 30,
            "max_crashes": 4,
            "collect_coverage": True,
        },
        PurePosixPath("/input/input.bin"),
        PurePosixPath("/output"),
    )
    assert argv == (
        "vulnweaver-fuzz-entrypoint",
        "--profile",
        "afl-qemu-casr",
        "--input-bundle",
        "/input/input.bin",
        "--output-dir",
        "/output",
        "--max-executions",
        "10",
        "--max-duration-seconds",
        "30",
        "--max-crashes",
        "4",
        "--collect-coverage",
    )
    with pytest.raises(ValueError, match="unsupported"):
        profile.build_argv(
            {
                "profile": "shell",
                "max_executions": 1,
                "max_duration_seconds": 1,
                "max_crashes": 1,
                "collect_coverage": False,
            },
            PurePosixPath("/input/input.bin"),
            PurePosixPath("/output"),
        )
