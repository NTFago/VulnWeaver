from __future__ import annotations

import asyncio
import io
import json
from pathlib import Path

from vulnweaver_artifact_store import LocalContentAddressedStore
from vulnweaver_binary_analysis import BinaryAnalysisLimits, BinaryFactsAdapter, inspect_binary
from vulnweaver_contracts import SandboxResult, SandboxStatus

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
    target.write_bytes(elf64_sample())
    contribution = asyncio.run(
        BinaryFactsAdapter(
            sandbox, store, image_digest="sha256:" + "a" * 64, input_ref="cas://sha256/" + "b" * 64
        ).analyze(
            target,
            inspect_binary(target, BinaryAnalysisLimits()),
            BinaryAnalysisLimits(),
            asyncio.Event(),
        )
    )
    assert contribution.compiler == "GCC"
    assert sandbox.request["output_file_names"] == ["binary-facts.json"]


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
    target.write_bytes(elf64_sample())
    adapter = BinaryFactsAdapter(
        _Sandbox(result),
        store,
        image_digest="sha256:" + "a" * 64,
        input_ref="cas://sha256/" + "b" * 64,
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
