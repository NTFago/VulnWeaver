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
from vulnweaver_artifact_store import LocalContentAddressedStore
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
    valid = _sandbox_result(store, minimized_values[0])
    manifest = json.dumps(
        {
            "schema_version": "1.0.0",
            "crashes": [
                {
                    "input_path": f"crash-000{i}",
                    "input_digest": "sha256:" + hashlib.sha256(minimized_values[i - 1]).hexdigest(),
                    "signal": "SIGSEGV",
                    "exit_code": -11,
                    "stack_frames": [f"#0 0x40100{i} in parse"],
                }
                for i in range(1, 6)
            ],
        }
    ).encode()
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w") as tar:
        for i in range(1, 6):
            info = tarfile.TarInfo(f"crash-000{i}")
            value = minimized_values[i - 1]
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
    fuzz_request = cast(
        FuzzRequest,
        {**request(target.object_ref, seed.object_ref), "max_crashes": 2},
    )

    result = asyncio.run(service.run(fuzz_request, asyncio.Event()))

    assert result["status"] == "partial"
    assert result["failure"] is not None
    assert result["failure"]["code"] == "fuzz.crash_budget_exceeded"
    assert len(result["crash_ids"]) == 2


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
