from __future__ import annotations

import io
import json
from pathlib import PurePosixPath
from typing import cast

import pytest
from vulnweaver_artifact_store import LocalContentAddressedStore
from vulnweaver_contracts import (
    JsonObject,
    ResourceBudget,
    SandboxResult,
    SandboxStatus,
    SchemaVersion,
    ToolSpec,
)
from vulnweaver_fuzzing import (
    HARNESS_COMPILE_PROFILE,
    HarnessCompileError,
    HarnessCompiler,
    HarnessPipeline,
    afl_casr_command_profile,
    afl_casr_tool_spec,
    build_harness_bundle,
)
from vulnweaver_tool_runtime import ToolRegistry

IMAGE_DIGEST = "sha256:" + "a" * 64
HARNESS_SOURCE = (
    "#include <stddef.h>\nint LLVMFuzzerTestOneInput(const unsigned char*d,size_t s){return 0;}\n"
)


def budget(**overrides: int) -> ResourceBudget:
    value: dict[str, int] = {
        "max_model_tokens": 0,
        "cpu_millis": 1000,
        "memory_bytes": 16 * 1024 * 1024,
        "disk_bytes": 4 * 1024 * 1024,
        "max_tool_concurrency": 1,
        "max_dynamic_runs": 1,
        "timeout_seconds": 60,
    }
    value.update(overrides)
    return cast(ResourceBudget, value)


def spec() -> ToolSpec:
    return afl_casr_tool_spec(IMAGE_DIGEST, budget())


def _output(store: LocalContentAddressedStore, name: str, value: bytes) -> dict[str, object]:
    stored = store.put_stream(io.BytesIO(value), max_bytes=8 * 1024 * 1024)
    return {
        "path": name,
        "object_ref": stored.object_ref,
        "digest": stored.digest,
        "size_bytes": stored.size_bytes,
    }


def _sandbox_result(
    store: LocalContentAddressedStore,
    *,
    success: bool,
    message: str = "",
    diagnostics: list[str] | None = None,
    harness: bytes = b"compiled-harness",
) -> SandboxResult:
    report = json.dumps(
        {
            "success": success,
            "message": message,
            "diagnostics": diagnostics or [],
        }
    ).encode()
    outputs = [_output(store, "compile-report.json", report)]
    if success:
        outputs.append(_output(store, "harness.tar", harness))
    return cast(
        SandboxResult,
        {
            "schema_version": "1.0.0",
            "request_id": "harness-compile:job-fuzz:0",
            "status": "succeeded",
            "exit_code": 0,
            "stdout_ref": None,
            "stderr_ref": None,
            "outputs": outputs,
            "resource_usage": {
                "duration_millis": 1,
                "cpu_millis": 1,
                "memory_bytes": 1,
                "output_bytes": 1,
            },
            "failure": None,
        },
    )


class _Sandbox:
    def __init__(self, results: list[SandboxResult]) -> None:
        self._results = results
        self.requests: list[dict[str, object]] = []

    async def run(self, request, _cancellation) -> SandboxResult:
        self.requests.append(dict(request))
        return self._results[min(len(self.requests) - 1, len(self._results) - 1)]


class _Generator:
    def __init__(self, source: str | None) -> None:
        self._source = source
        self.calls = 0

    async def generate(self, *, task_id, job_id, context) -> str | None:
        self.calls += 1
        return self._source


class _Repairer:
    """Returns a distinct repair per call unless a fixed candidate is given."""

    def __init__(self, repaired: str | None = None, *, distinct: bool = False) -> None:
        self._repaired = repaired
        self._distinct = distinct
        self.calls = 0
        self.seen: list[str] = []

    async def repair(self, *, task_id, job_id, source, diagnostics) -> str | None:
        self.calls += 1
        self.seen.append(diagnostics)
        if self._distinct:
            return f"int main(void){{return {self.calls};}}\n"
        return self._repaired


def _compiler(store: LocalContentAddressedStore, sandbox: _Sandbox) -> HarnessCompiler:
    return HarnessCompiler(store, ToolRegistry([spec()]), sandbox)


@pytest.mark.anyio
async def test_compile_uses_the_fixed_harness_profile(tmp_path) -> None:
    store = LocalContentAddressedStore(str(tmp_path / "cas"))
    sandbox = _Sandbox([_sandbox_result(store, success=True)])
    compiler = _compiler(store, sandbox)

    outcome = await compiler.compile(
        HARNESS_SOURCE,
        request_id="harness-compile:job-fuzz:0",
        artifact_version_id="artifact-version:1",
        budget=budget(),
    )

    assert outcome.succeeded
    assert outcome.compiled_ref is not None
    request = sandbox.requests[0]
    assert request["tool_name"] == "afl-casr"
    assert request["image_digest"] == IMAGE_DIGEST
    assert request["arguments"] == {"profile": HARNESS_COMPILE_PROFILE}
    assert set(cast(list[str], request["output_file_names"])) == {
        "compile-report.json",
        "harness.tar",
    }


@pytest.mark.anyio
async def test_compile_reports_structured_diagnostics_without_a_harness(tmp_path) -> None:
    store = LocalContentAddressedStore(str(tmp_path / "cas"))
    result = _sandbox_result(
        store,
        success=False,
        message="harness.c:3: error",
        diagnostics=["missing prototype", "undefined reference"],
    )
    compiler = _compiler(store, _Sandbox([result]))

    outcome = await compiler.compile(
        HARNESS_SOURCE,
        request_id="harness-compile:job-fuzz:0",
        artifact_version_id="artifact-version:1",
        budget=budget(),
    )

    assert not outcome.succeeded
    assert outcome.compiled_ref is None
    assert outcome.diagnostics == ("missing prototype", "undefined reference")


@pytest.mark.anyio
async def test_compile_without_a_registered_tool_is_a_structured_failure(tmp_path) -> None:
    store = LocalContentAddressedStore(str(tmp_path / "cas"))
    compiler = HarnessCompiler(store, ToolRegistry(), _Sandbox([]))

    outcome = await compiler.compile(
        HARNESS_SOURCE,
        request_id="r",
        artifact_version_id="artifact-version:1",
        budget=budget(),
    )

    assert not outcome.succeeded
    assert outcome.compiled_ref is None


def test_harness_bundle_is_deterministic_and_rejects_an_oversized_source(tmp_path) -> None:
    store = LocalContentAddressedStore(str(tmp_path / "cas"))

    first = build_harness_bundle(store, HARNESS_SOURCE)
    second = build_harness_bundle(store, HARNESS_SOURCE)

    assert first.object_ref == second.object_ref
    with pytest.raises(HarnessCompileError):
        build_harness_bundle(store, "x" * 70000)


@pytest.mark.anyio
async def test_pipeline_repairs_once_then_compiles(tmp_path) -> None:
    store = LocalContentAddressedStore(str(tmp_path / "cas"))
    sandbox = _Sandbox(
        [
            _sandbox_result(store, success=False, message="syntax error", diagnostics=["boom"]),
            _sandbox_result(store, success=True),
        ]
    )
    compiler = _compiler(store, sandbox)
    repairer = _Repairer("int main(void){return 0;}\n")
    pipeline = HarnessPipeline(
        compiler, generator=_Generator(HARNESS_SOURCE), repairer=repairer, max_repairs=2
    )

    result = await pipeline.build(
        task_id="task",
        job_id="job-fuzz",
        artifact_version_id="artifact-version:1",
        context=cast(JsonObject, {}),
        budget=budget(),
    )

    assert result.succeeded
    assert result.status == "compiled"
    assert repairer.calls == 1
    assert repairer.seen == ["boom"]
    assert len(result.diagnostics) == 2


@pytest.mark.anyio
async def test_pipeline_exhausts_its_budget_without_looping(tmp_path) -> None:
    store = LocalContentAddressedStore(str(tmp_path / "cas"))
    sandbox = _Sandbox([_sandbox_result(store, success=False, message="still broken")])
    compiler = _compiler(store, sandbox)
    repairer = _Repairer(distinct=True)
    pipeline = HarnessPipeline(
        compiler, generator=_Generator(HARNESS_SOURCE), repairer=repairer, max_repairs=2
    )

    result = await pipeline.build(
        task_id="task",
        job_id="job-fuzz",
        artifact_version_id="artifact-version:1",
        context=cast(JsonObject, {}),
        budget=budget(),
    )

    # Two repairs plus the initial attempt: the budget is exact, never exceeded.
    assert result.status == "failed"
    assert result.compiled_ref is None
    assert len(sandbox.requests) == 3
    assert repairer.calls == 2
    assert result.loop is not None and result.loop.status == "failed"


@pytest.mark.anyio
async def test_pipeline_stops_when_the_repair_is_not_an_improvement(tmp_path) -> None:
    store = LocalContentAddressedStore(str(tmp_path / "cas"))
    sandbox = _Sandbox([_sandbox_result(store, success=False, message="broken")])
    compiler = _compiler(store, sandbox)
    pipeline = HarnessPipeline(
        compiler,
        generator=_Generator(HARNESS_SOURCE),
        repairer=_Repairer(HARNESS_SOURCE),
        max_repairs=3,
    )

    result = await pipeline.build(
        task_id="task",
        job_id="job-fuzz",
        artifact_version_id="artifact-version:1",
        context=cast(JsonObject, {}),
        budget=budget(),
    )

    assert result.status == "failed"
    assert len(sandbox.requests) == 1


@pytest.mark.anyio
async def test_pipeline_without_a_generator_is_unconfigured(tmp_path) -> None:
    store = LocalContentAddressedStore(str(tmp_path / "cas"))
    compiler = HarnessCompiler(store, ToolRegistry([spec()]), _Sandbox([]))
    pipeline = HarnessPipeline(compiler)

    result = await pipeline.build(
        task_id="task",
        job_id="job-fuzz",
        artifact_version_id="artifact-version:1",
        context=cast(JsonObject, {}),
        budget=budget(),
    )

    assert result.status == "unconfigured"
    assert not result.succeeded


def test_pipeline_rejects_an_out_of_range_repair_budget(tmp_path) -> None:
    store = LocalContentAddressedStore(str(tmp_path / "cas"))
    compiler = HarnessCompiler(store, ToolRegistry([spec()]), _Sandbox([]))

    with pytest.raises(ValueError):
        HarnessPipeline(compiler, max_repairs=9)


def test_harness_compile_profile_builds_a_compile_only_argv() -> None:
    profile = afl_casr_command_profile("vulnweaver-afl-casr:fixed", IMAGE_DIGEST)
    argv = profile.build_argv(
        {"profile": HARNESS_COMPILE_PROFILE},
        PurePosixPath("/in.bin"),
        PurePosixPath("/out"),
    )

    assert argv == (
        "vulnweaver-fuzz-entrypoint",
        "--profile",
        "harness-compile",
        "--input-bundle",
        "/in.bin",
        "--output-dir",
        "/out",
    )


def test_sandbox_result_helper_is_well_formed(tmp_path) -> None:
    """Guard the fixture itself: an invalid SandboxResult would mask real failures."""
    store = LocalContentAddressedStore(str(tmp_path / "cas"))
    result = _sandbox_result(store, success=True)

    assert result["status"] == SandboxStatus.SUCCEEDED.value
    assert result["schema_version"] == SchemaVersion.VALUE_1_0_0.value
    assert {item["path"] for item in cast(list[dict[str, object]], result["outputs"])} == {
        "compile-report.json",
        "harness.tar",
    }
