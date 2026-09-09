from __future__ import annotations

import asyncio
import copy
import io
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from vulnweaver_artifact_store import LocalContentAddressedStore
from vulnweaver_contracts import (
    ArtifactKind,
    FailureKind,
    NetworkAccess,
    ResourceBudget,
    SandboxRequest,
    SandboxStatus,
    SchemaVersion,
    ToolSpec,
)
from vulnweaver_sandbox_runner import (
    DockerCliRuntime,
    RuntimeExecution,
    RuntimeRequest,
    SandboxCommandProfile,
    SandboxRunner,
)
from vulnweaver_tool_runtime import ToolRegistry

IMAGE_DIGEST = "sha256:" + "a" * 64


def budget(**overrides: int) -> ResourceBudget:
    value: dict[str, int] = {
        "max_model_tokens": 0,
        "cpu_millis": 1000,
        "memory_bytes": 16 * 1024 * 1024,
        "disk_bytes": 1024 * 1024,
        "max_tool_concurrency": 1,
        "max_dynamic_runs": 0,
        "timeout_seconds": 30,
    }
    value.update(overrides)
    return cast(ResourceBudget, value)


def spec() -> ToolSpec:
    return cast(
        ToolSpec,
        {
            "schema_version": "1.0.0",
            "name": "safe-test-tool",
            "version": "1.0.0",
            "image_digest": IMAGE_DIGEST,
            "risk_level": "high",
            "accepted_artifacts": ["source_archive"],
            "command_schema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["profile"],
                "properties": {
                    "profile": {"type": "string", "enum": ["safe"]},
                },
            },
            "output_schema": {"type": "object"},
            "network_policy": {"access": "none", "allowed_hosts": []},
            "filesystem_policy": {
                "input_read_only": True,
                "isolated_output": True,
                "allow_host_paths": False,
            },
            "resource_limits": budget(),
            "approval_required": False,
            "timeout_seconds": 30,
            "retry_policy": {
                "max_attempts": 1,
                "backoff_seconds": 0,
                "retryable_failure_kinds": [],
            },
        },
    )


def request(
    *, image_digest: str = IMAGE_DIGEST, artifact_kind: ArtifactKind = ArtifactKind.SOURCE_ARCHIVE
) -> SandboxRequest:
    return SandboxRequest(
        schema_version=SchemaVersion.VALUE_1_0_0,
        id="sandbox-request:test-001",
        tool_name="safe-test-tool",
        tool_version="1.0.0",
        image_digest=image_digest,
        artifact_kind=artifact_kind,
        input_ref="cas://sha256/" + "b" * 64,
        arguments={"profile": "safe"},
        output_file_names=["report.txt"],
        resource_budget=budget(),
        timeout_seconds=10,
    )


class _FakeRuntime:
    def __init__(self, *, cleanup_result: bool = True, unexpected_output: bool = False) -> None:
        self.cleanup_result = cleanup_result
        self.unexpected_output = unexpected_output
        self.requests: list[RuntimeRequest] = []
        self.cleaned: list[str] = []

    async def run(self, request: RuntimeRequest, cancellation: asyncio.Event) -> RuntimeExecution:
        self.requests.append(request)
        if cancellation.is_set():
            return RuntimeExecution("cancelled", None, b"", b"", 1, 0, 0)
        (request.output_dir / "report.txt").write_text("safe output", encoding="utf-8")
        if self.unexpected_output:
            (request.output_dir / "secret.txt").write_text("unexpected", encoding="utf-8")
        return RuntimeExecution("succeeded", 0, b"stdout", b"", 12, 3, 4096)

    async def cleanup(self, container_name: str) -> bool:
        self.cleaned.append(container_name)
        return self.cleanup_result

    async def list_owned(self, label: str) -> tuple[str, ...]:
        del label
        return ("vw-sbx-orphan", "invalid name")


def runner(
    tmp_path: Path, runtime: _FakeRuntime
) -> tuple[SandboxRunner, LocalContentAddressedStore]:
    store = LocalContentAddressedStore(tmp_path / "cas")
    input_object = store.put_stream(io.BytesIO(b"authorized input"), max_bytes=1024)
    value = request()
    value["input_ref"] = input_object.object_ref
    registry = ToolRegistry([spec()])
    profile = SandboxCommandProfile(
        tool_name="safe-test-tool",
        tool_version="1.0.0",
        image_ref="registry.example/safe-tool",
        image_digest=IMAGE_DIGEST,
        build_argv=lambda arguments, input_path, output_path: (
            "tool-entrypoint",
            "--profile",
            str(arguments["profile"]),
            "--input",
            str(input_path),
            "--output-dir",
            str(output_path),
        ),
    )
    return (
        SandboxRunner(
            store,
            registry,
            [profile],
            runtime=runtime,
            root=tmp_path / "sandbox",
        ),
        store,
    )


def test_runner_validates_exact_tool_identity_publishes_outputs_and_cleans_up(
    tmp_path: Path,
) -> None:
    runtime = _FakeRuntime()
    sandbox, store = runner(tmp_path, runtime)

    invalid = cast(SandboxRequest, {"id": "sandbox-request:invalid"})
    result = asyncio.run(sandbox.run(invalid, asyncio.Event()))

    # The helper creates the CAS input object; recreate the request with that object.
    assert result["status"] is SandboxStatus.POLICY_DENIED
    assert result["failure"] is not None
    assert result["failure"]["kind"] is FailureKind.POLICY
    assert not runtime.requests

    input_object = store.put_stream(io.BytesIO(b"authorized input"), max_bytes=1024)
    valid = request()
    valid["input_ref"] = input_object.object_ref
    result = asyncio.run(sandbox.run(valid, asyncio.Event()))

    assert result["status"] is SandboxStatus.SUCCEEDED
    assert result["exit_code"] == 0
    assert result["stdout_ref"] is not None
    assert result["outputs"][0]["path"] == "report.txt"
    assert store.verify(result["stdout_ref"]).size_bytes == len(b"stdout")
    assert store.verify(result["outputs"][0]["object_ref"]).size_bytes == len("safe output")
    assert runtime.requests[0].image_ref == "registry.example/safe-tool"
    assert runtime.requests[0].argv[0] == "tool-entrypoint"
    assert "/input/input.bin" in runtime.requests[0].argv
    assert "/output" in runtime.requests[0].argv
    assert len(runtime.cleaned) == 1


def test_runner_rejects_tool_specs_that_violate_mandatory_isolation(
    tmp_path: Path,
) -> None:
    runtime = _FakeRuntime()
    store = LocalContentAddressedStore(tmp_path / "cas")
    input_object = store.put_stream(io.BytesIO(b"input"), max_bytes=1024)
    unsafe = copy.deepcopy(spec())
    unsafe["network_policy"] = {
        "access": NetworkAccess.ALLOWLIST,
        "allowed_hosts": ["example.test"],
    }
    registry = ToolRegistry([unsafe])
    profile = SandboxCommandProfile(
        tool_name="safe-test-tool",
        tool_version="1.0.0",
        image_ref="registry.example/safe-tool",
        image_digest=IMAGE_DIGEST,
        build_argv=lambda arguments, input_path, output_path: (
            "tool-entrypoint",
            str(arguments["profile"]),
            str(input_path),
            str(output_path),
        ),
    )
    sandbox = SandboxRunner(
        store,
        registry,
        [profile],
        runtime=runtime,
        root=tmp_path / "sandbox",
    )
    value = request()
    value["input_ref"] = input_object.object_ref

    result = asyncio.run(sandbox.run(value, asyncio.Event()))

    assert result["status"] is SandboxStatus.POLICY_DENIED
    assert result["failure"] is not None
    assert result["failure"]["code"] == "sandbox.isolation_policy_rejected"
    assert runtime.requests == []


def test_runner_denies_image_artifact_and_argument_policy_violations(tmp_path: Path) -> None:
    runtime = _FakeRuntime()
    sandbox, store = runner(tmp_path, runtime)
    input_object = store.put_stream(io.BytesIO(b"input"), max_bytes=1024)

    wrong_image = request(image_digest="sha256:" + "c" * 64)
    wrong_image["input_ref"] = input_object.object_ref
    wrong_kind = request(artifact_kind=ArtifactKind.PE)
    wrong_kind["input_ref"] = input_object.object_ref
    extra_argument = request()
    extra_argument["input_ref"] = input_object.object_ref
    extra_argument["arguments"]["shell"] = "not-allowed"

    for value, code in (
        (wrong_image, "sandbox.image_identity_mismatch"),
        (wrong_kind, "sandbox.artifact_kind_rejected"),
        (extra_argument, "sandbox.arguments_rejected"),
    ):
        result = asyncio.run(sandbox.run(value, asyncio.Event()))
        assert result["status"] is SandboxStatus.POLICY_DENIED
        assert result["failure"] is not None
        assert result["failure"]["code"] == code
    assert not runtime.requests


def test_runner_rejects_unapproved_output_and_reports_orphan_cleanup(tmp_path: Path) -> None:
    runtime = _FakeRuntime(unexpected_output=True, cleanup_result=False)
    sandbox, store = runner(tmp_path, runtime)
    input_object = store.put_stream(io.BytesIO(b"input"), max_bytes=1024)
    value = request()
    value["input_ref"] = input_object.object_ref

    result = asyncio.run(sandbox.run(value, asyncio.Event()))

    assert result["status"] is SandboxStatus.ORPHANED
    assert result["failure"] is not None
    assert result["failure"]["code"] == "sandbox.cleanup_failed"
    assert result["outputs"] == []
    assert len(runtime.cleaned) == 1


def test_runner_recovers_only_owned_safe_container_names(tmp_path: Path) -> None:
    runtime = _FakeRuntime()
    sandbox, _ = runner(tmp_path, runtime)

    recovered = asyncio.run(sandbox.recover_orphans())

    assert recovered == ("vw-sbx-orphan",)
    assert runtime.cleaned == ["vw-sbx-orphan"]


def test_docker_runtime_builds_fixed_isolated_flags_and_rejects_host_mounts(
    tmp_path: Path,
) -> None:
    runtime = DockerCliRuntime(root=tmp_path)
    value = RuntimeRequest(
        container_name="vw-sbx-test",
        label="vulnweaver.sandbox=true",
        image_ref="registry.example/tool",
        image_digest=IMAGE_DIGEST,
        argv=("entrypoint", "--input", "/input/input.bin"),
        input_dir=tmp_path / "input",
        output_dir=tmp_path / "output",
        resource_budget=budget(),
        timeout_seconds=10,
        max_output_bytes=1024,
    )
    value.input_dir.mkdir()
    value.output_dir.mkdir()
    arguments = runtime.build_arguments(value)
    assert "--network" in arguments and arguments[arguments.index("--network") + 1] == "none"
    assert "--read-only" in arguments
    assert arguments[arguments.index("--cap-drop") + 1] == "ALL"
    assert "--privileged" not in arguments
    assert "--user" in arguments and "10001:10001" in arguments
    assert any("readonly" in item for item in arguments if item.startswith("type=bind"))

    outside = replace(value, input_dir=tmp_path.parent / "outside")
    with pytest.raises(ValueError):
        runtime.validate_request(outside)
