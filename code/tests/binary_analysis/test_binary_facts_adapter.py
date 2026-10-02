from __future__ import annotations

import asyncio
import io
import json
from pathlib import Path
from typing import cast

import pytest
from vulnweaver_artifact_store import LocalContentAddressedStore
from vulnweaver_binary_analysis import BinaryAnalysisLimits, BinaryFactsAdapter, inspect_binary
from vulnweaver_binary_analysis.tools import ToolCancelled, ToolExecutionError
from vulnweaver_contracts import FailureKind, SandboxResult, SandboxStatus

from tests.binary_analysis.samples import elf64_sample


class _Sandbox:
    def __init__(self, result: SandboxResult) -> None:
        self.result = result
        self.request = None

    async def run(self, request, cancellation: asyncio.Event) -> SandboxResult:
        del cancellation
        self.request = request
        return self.result


def test_binary_facts_adapter_converts_cas_output(tmp_path: Path) -> None:
    store = LocalContentAddressedStore(tmp_path / "cas")
    payload = {
        "tools": {
            "objdump": {
                "run": {
                    "tool_name": "objdump",
                    "tool_version": "2.40",
                    "status": "succeeded",
                    "exit_code": 0,
                    "reason": None,
                    "raw_output": None,
                }
            },
            "die": {"compiler": "GCC", "packer": None, "packed": False},
        },
        "functions": [],
        "instructions": [],
        "basic_blocks": [],
        "xrefs": [],
        "pseudocode": [],
    }
    stored = store.put_stream(io.BytesIO(json.dumps(payload).encode()), max_bytes=1024 * 1024)
    result = SandboxResult(
        schema_version="1.0.0",
        request_id="request-1",
        status=SandboxStatus.SUCCEEDED,
        exit_code=0,
        stdout_ref=None,
        stderr_ref=None,
        outputs=[
            {
                "path": "binary-facts.json",
                "object_ref": stored.object_ref,
                "digest": stored.digest,
                "size_bytes": stored.size_bytes,
            }
        ],
        resource_usage={
            "duration_millis": 1,
            "cpu_millis": 1,
            "memory_bytes": 1,
            "output_bytes": stored.size_bytes,
        },
        failure=None,
    )
    sandbox = _Sandbox(result)
    target = tmp_path / "sample"
    sample = elf64_sample()
    target.write_bytes(sample)
    pinned = store.put_stream(io.BytesIO(sample), max_bytes=1024 * 1024)
    contribution = asyncio.run(
        BinaryFactsAdapter(
            sandbox,
            store,
            image_digest="sha256:" + "a" * 64,
            input_ref=pinned.object_ref,
        ).analyze(
            target,
            inspect_binary(target, BinaryAnalysisLimits()),
            BinaryAnalysisLimits(),
            asyncio.Event(),
        )
    )
    assert contribution.compiler == "GCC"
    assert sandbox.request["output_file_names"] == ["binary-facts.json"]
    assert sandbox.request["input_ref"] == pinned.object_ref


def test_binary_facts_adapter_rejects_missing_output(tmp_path: Path) -> None:
    store = LocalContentAddressedStore(tmp_path / "cas")
    result = SandboxResult(
        schema_version="1.0.0",
        request_id="request-1",
        status=SandboxStatus.SUCCEEDED,
        exit_code=0,
        stdout_ref=None,
        stderr_ref=None,
        outputs=[],
        resource_usage={
            "duration_millis": 1,
            "cpu_millis": 1,
            "memory_bytes": 1,
            "output_bytes": 0,
        },
        failure=None,
    )
    target = tmp_path / "sample"
    sample = elf64_sample()
    target.write_bytes(sample)
    pinned = store.put_stream(io.BytesIO(sample), max_bytes=1024 * 1024)
    adapter = BinaryFactsAdapter(
        _Sandbox(result),
        store,
        image_digest="sha256:" + "a" * 64,
        input_ref=pinned.object_ref,
    )
    try:
        asyncio.run(
            adapter.analyze(
                target,
                inspect_binary(target, BinaryAnalysisLimits()),
                BinaryAnalysisLimits(),
                asyncio.Event(),
            )
        )
    except RuntimeError as error:
        assert str(error) == "binary-facts output is missing"
    else:
        raise AssertionError("missing binary-facts output was accepted")


def test_binary_facts_adapter_refuses_to_analyze_a_different_artifact(tmp_path: Path) -> None:
    """The sandbox reads its input by CAS reference, never from `path`.

    Handing this adapter the unpacked image while it keeps analysing the packed
    original produced a wrong answer that looked entirely plausible, so the
    mismatch has to be an error rather than a silent substitution.
    """
    store = LocalContentAddressedStore(tmp_path / "cas")
    target = tmp_path / "sample"
    target.write_bytes(elf64_sample())
    other = store.put_stream(io.BytesIO(b"\x7fELF" + b"\x00" * 64), max_bytes=1024 * 1024)
    adapter = BinaryFactsAdapter(
        _Sandbox(cast(SandboxResult, None)),
        store,
        image_digest="sha256:" + "a" * 64,
        input_ref=other.object_ref,
    )
    try:
        asyncio.run(
            adapter.analyze(
                target,
                inspect_binary(target, BinaryAnalysisLimits()),
                BinaryAnalysisLimits(),
                asyncio.Event(),
            )
        )
    except RuntimeError as error:
        assert str(error) == "binary-facts input_ref does not match the artifact being analyzed"
    else:
        raise AssertionError("a mismatched input_ref was accepted")


def _failed_result(status: SandboxStatus, code: str, retryable: bool) -> SandboxResult:
    return SandboxResult(
        schema_version="1.0.0",
        request_id="request-1",
        status=status,
        exit_code=None,
        stdout_ref=None,
        stderr_ref=None,
        outputs=[],
        resource_usage={
            "duration_millis": 1,
            "cpu_millis": 1,
            "memory_bytes": 1,
            "output_bytes": 0,
        },
        failure={
            "code": code,
            "kind": "timeout" if code == "sandbox.timeout" else "dependency",
            "message": "sandbox tool exceeded its time limit",
            "retryable": retryable,
            "details": {},
        },
    )


def test_binary_facts_adapter_maps_timeout_to_retryable_failure(tmp_path: Path) -> None:
    """A runner-side timeout is an operational stop the retry policy can act on.

    The request must also carry the configured command timeout verbatim: the
    old ``min(600, ...)`` cap silently ignored larger configured limits.
    """

    store = LocalContentAddressedStore(tmp_path / "cas")
    result = _failed_result(SandboxStatus.TIMED_OUT, "sandbox.timeout", retryable=True)
    sandbox = _Sandbox(result)
    limits = BinaryAnalysisLimits(command_timeout_seconds=1234)
    target = tmp_path / "sample"
    target.write_bytes(elf64_sample())
    pinned = store.put_stream(io.BytesIO(elf64_sample()), max_bytes=1024 * 1024)
    adapter = BinaryFactsAdapter(
        sandbox,
        store,
        image_digest="sha256:" + "a" * 64,
        input_ref=pinned.object_ref,
    )
    try:
        asyncio.run(
            adapter.analyze(
                target,
                inspect_binary(target, limits),
                limits,
                asyncio.Event(),
            )
        )
    except RuntimeError as error:
        assert "sandbox.timeout" in str(error)
        assert isinstance(error, ToolExecutionError)
        assert error.kind is FailureKind.TIMEOUT
        assert error.retryable is True
        assert error.details["failure_code"] == "sandbox.timeout"
    else:
        raise AssertionError("a timed-out sandbox run was treated as success")
    assert sandbox.request["timeout_seconds"] == 1234
    assert sandbox.request["arguments"]["command_timeout_seconds"] == 1234


@pytest.mark.parametrize(
    ("code", "expected_kind"),
    [
        ("sandbox.transport_failed", FailureKind.ENVIRONMENT),
        ("sandbox.runtime_failed", FailureKind.ENVIRONMENT),
    ],
)
def test_binary_facts_adapter_maps_operational_failures_to_retryable_environment(
    tmp_path: Path, code: str, expected_kind: FailureKind
) -> None:
    """Runner-unreachable and container-start failures retry under the policy."""

    store = LocalContentAddressedStore(tmp_path / "cas")
    result = _failed_result(SandboxStatus.FAILED, code, retryable=True)
    target = tmp_path / "sample"
    target.write_bytes(elf64_sample())
    pinned = store.put_stream(io.BytesIO(elf64_sample()), max_bytes=1024 * 1024)
    try:
        asyncio.run(
            BinaryFactsAdapter(
                _Sandbox(result),
                store,
                image_digest="sha256:" + "a" * 64,
                input_ref=pinned.object_ref,
            ).analyze(
                target,
                inspect_binary(target, BinaryAnalysisLimits()),
                BinaryAnalysisLimits(),
                asyncio.Event(),
            )
        )
    except ToolExecutionError as error:
        assert error.kind is expected_kind
        assert error.retryable is True
    else:
        raise AssertionError(f"{code} was treated as success")


def test_binary_facts_adapter_maps_runner_cancellation_to_tool_cancelled(
    tmp_path: Path,
) -> None:
    """A runner-side cancellation means the worker is going away, not failing."""

    store = LocalContentAddressedStore(tmp_path / "cas")
    result = _failed_result(SandboxStatus.CANCELLED, "sandbox.cancelled", retryable=False)
    target = tmp_path / "sample"
    target.write_bytes(elf64_sample())
    pinned = store.put_stream(io.BytesIO(elf64_sample()), max_bytes=1024 * 1024)
    try:
        asyncio.run(
            BinaryFactsAdapter(
                _Sandbox(result),
                store,
                image_digest="sha256:" + "a" * 64,
                input_ref=pinned.object_ref,
            ).analyze(
                target,
                inspect_binary(target, BinaryAnalysisLimits()),
                BinaryAnalysisLimits(),
                asyncio.Event(),
            )
        )
    except ToolCancelled:
        pass
    else:
        raise AssertionError("a cancelled sandbox run was treated as success")


def _facts_result(
    store: LocalContentAddressedStore,
    *,
    functions: list[dict[str, object]],
    objdump_status: str,
    objdump_reason: str | None,
    ghidra_status: str,
    ghidra_reason: str | None,
) -> SandboxResult:
    payload = {
        "tools": {
            "objdump": {
                "tool_name": "objdump",
                "tool_version": "2.40",
                "status": objdump_status,
                "exit_code": 0 if objdump_status == "succeeded" else None,
                "reason": objdump_reason,
                "raw_output": None,
            },
            "ghidra": {
                "tool_name": "ghidra",
                "tool_version": "11.4",
                "status": ghidra_status,
                "exit_code": 0 if ghidra_status == "succeeded" else None,
                "reason": ghidra_reason,
                "raw_output": None,
            },
            "die": {"compiler": "GCC", "packer": None, "packed": False},
        },
        "functions": functions,
        "instructions": [],
        "basic_blocks": [],
        "xrefs": [],
        "pseudocode": [],
    }
    stored = store.put_stream(io.BytesIO(json.dumps(payload).encode()), max_bytes=1024 * 1024)
    return SandboxResult(
        schema_version="1.0.0",
        request_id="request-1",
        status=SandboxStatus.SUCCEEDED,
        exit_code=0,
        stdout_ref=None,
        stderr_ref=None,
        outputs=[
            {
                "path": "binary-facts.json",
                "object_ref": stored.object_ref,
                "digest": stored.digest,
                "size_bytes": stored.size_bytes,
            }
        ],
        resource_usage={
            "duration_millis": 1,
            "cpu_millis": 1,
            "memory_bytes": 1,
            "output_bytes": stored.size_bytes,
        },
        failure=None,
    )


def test_binary_facts_adapter_fails_loudly_when_both_sources_failed(
    tmp_path: Path,
) -> None:
    """Ghidra timeout + objdump overflow with no functions is a retryable failure.

    This is the silent wrong answer that cost twenty minutes of Ghidra on an
    18MB PE and published an empty analysis that looked successful: the run
    must fail instead, with the per-tool reasons in the details.
    """

    store = LocalContentAddressedStore(tmp_path / "cas")
    result = _facts_result(
        store,
        functions=[],
        objdump_status="failed",
        objdump_reason="output_limit_exceeded",
        ghidra_status="failed",
        ghidra_reason="timeout",
    )
    target = tmp_path / "sample"
    target.write_bytes(elf64_sample())
    pinned = store.put_stream(io.BytesIO(elf64_sample()), max_bytes=1024 * 1024)
    try:
        asyncio.run(
            BinaryFactsAdapter(
                _Sandbox(result),
                store,
                image_digest="sha256:" + "a" * 64,
                input_ref=pinned.object_ref,
            ).analyze(
                target,
                inspect_binary(target, BinaryAnalysisLimits()),
                BinaryAnalysisLimits(),
                asyncio.Event(),
            )
        )
    except ToolExecutionError as error:
        assert error.kind is FailureKind.TOOL
        assert error.retryable is True
        assert error.details["failure_code"] == "facts_sources_failed"
        assert "timeout" in str(error)
        assert "output_limit_exceeded" in str(error)
    else:
        raise AssertionError("a facts run with no functions and both sources failed succeeded")


def test_binary_facts_adapter_keeps_partial_objdump_when_ghidra_failed(
    tmp_path: Path,
) -> None:
    """Ghidra failing alone is not fatal: objdump's functions still land."""

    store = LocalContentAddressedStore(tmp_path / "cas")
    sample = elf64_sample()
    functions = [
        {"name": "main", "address": 0x1050, "size": 7, "file_offset": 0x200}
    ]
    result = _facts_result(
        store,
        functions=functions,
        objdump_status="succeeded",
        objdump_reason="output_truncated",
        ghidra_status="failed",
        ghidra_reason="timeout",
    )
    target = tmp_path / "sample"
    target.write_bytes(sample)
    pinned = store.put_stream(io.BytesIO(sample), max_bytes=1024 * 1024)
    contribution = asyncio.run(
        BinaryFactsAdapter(
            _Sandbox(result),
            store,
            image_digest="sha256:" + "a" * 64,
            input_ref=pinned.object_ref,
        ).analyze(
            target,
            inspect_binary(target, BinaryAnalysisLimits()),
            BinaryAnalysisLimits(),
            asyncio.Event(),
        )
    )
    assert [function["name"] for function in contribution.functions] == ["main"]
    assert contribution.run["status"] == "succeeded"
    assert contribution.run["reason"] == "output_truncated"


def test_binary_facts_adapter_angr_only_follow_up(tmp_path: Path) -> None:
    """A symbolic-target follow-up returns only angr's facts and run row."""

    store = LocalContentAddressedStore(tmp_path / "cas")
    payload = {
        "tools": {
            "angr": {
                "tool_name": "angr",
                "tool_version": None,
                "status": "succeeded",
                "exit_code": 0,
                "reason": None,
                "raw_output": None,
            }
        },
        "functions": [],
        "symbolic_facts": [
            {
                "function_address": 4144,
                "status": "completed",
                "steps": 3,
                "explored_states": 5,
                "reached_addresses": [4200],
                "unconstrained_states": 0,
                "reason": None,
            }
        ],
    }
    stored = store.put_stream(io.BytesIO(json.dumps(payload).encode()), max_bytes=1024 * 1024)
    result = SandboxResult(
        schema_version="1.0.0",
        request_id="request-1",
        status=SandboxStatus.SUCCEEDED,
        exit_code=0,
        stdout_ref=None,
        stderr_ref=None,
        outputs=[
            {
                "path": "binary-facts.json",
                "object_ref": stored.object_ref,
                "digest": stored.digest,
                "size_bytes": stored.size_bytes,
            }
        ],
        resource_usage={
            "duration_millis": 1,
            "cpu_millis": 1,
            "memory_bytes": 1,
            "output_bytes": stored.size_bytes,
        },
        failure=None,
    )
    sandbox = _Sandbox(result)
    sample = elf64_sample()
    target = tmp_path / "sample"
    target.write_bytes(sample)
    pinned = store.put_stream(io.BytesIO(sample), max_bytes=1024 * 1024)
    contribution = asyncio.run(
        BinaryFactsAdapter(
            sandbox,
            store,
            image_digest="sha256:" + "a" * 64,
            input_ref=pinned.object_ref,
            target_addresses=(4144,),
            angr_enabled=True,
            skip_disassembly=True,
        ).analyze_ref("elf", BinaryAnalysisLimits(), asyncio.Event())
    )
    assert sandbox.request["arguments"]["skip_disassembly"] is True
    assert [fact["function_address"] for fact in contribution.symbolic_facts] == [4144]
    assert contribution.functions == ()
    assert contribution.run["tool_name"] == "angr"
