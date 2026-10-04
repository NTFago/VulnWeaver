"""Sandbox binary-facts entrypoint: the facts document must be constructible.

The entrypoint runs as its own program inside the sandbox image, so nothing in
the worker-facing test suite ever executed `_facts_mode` — `BinaryFactsAdapter`
only reads back the JSON the entrypoint produced, and it never runs the script.
That gap let a real break through: CR-08 changed `extract_strings` to return a
`StringExtraction` wrapper instead of a plain tuple, and the entrypoint kept
calling `list(...)` on the result. `StringExtraction` is a frozen, slotted
dataclass with no `__iter__`, so the document construction raised
`TypeError: 'StringExtraction' object is not iterable`. `main()` converts any
exception into exit code 1, so every sandboxed binary import failed as a tool
error instead of producing binary-facts.json.

These tests drive the real `_facts_mode` against a real sample with the tool
adapters stubbed, which keeps the document construction — including the strings
consumer — covered without needing Ghidra, objdump or angr in the test image.
"""

from __future__ import annotations

import argparse
import asyncio
import importlib.util
import json
from importlib.machinery import SourceFileLoader
from pathlib import Path
from typing import Any

from vulnweaver_binary_analysis import (
    BinaryAnalysisLimits,
    ToolContribution,
    UpxOutcome,
    inspect_binary,
)

from tests.binary_analysis.samples import elf64_sample

ENTRYPOINT = (
    Path(__file__).resolve().parents[2] / "apps/binary-tools/vulnweaver-binary-entrypoint"
)


def _load_entrypoint() -> Any:
    loader = SourceFileLoader("binary_entrypoint_under_test", str(ENTRYPOINT))
    spec = importlib.util.spec_from_loader("binary_entrypoint_under_test", loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _tool_run(name: str) -> dict[str, object]:
    return {
        "tool_name": name,
        "tool_version": "1.0.0",
        "status": "succeeded",
        "exit_code": 0,
        "reason": None,
        "raw_output": None,
    }


class _FakeDie:
    def __init__(self, *_: object, **__: object) -> None:
        pass

    async def analyze(self, *_args: object) -> ToolContribution:
        return ToolContribution(
            run=_tool_run("die"), compiler="gcc", packer=None, packed=False
        )


class _FakeUpx:
    def __init__(self, *_: object, **__: object) -> None:
        pass

    async def unpack(self, *_args: object) -> UpxOutcome:
        return UpxOutcome(run=_tool_run("upx"), packed=False, unpacked_path=None)


class _FakeObjdump:
    def __init__(self, *_: object, **__: object) -> None:
        pass

    async def analyze(self, *_args: object) -> ToolContribution:
        return ToolContribution(run=_tool_run("objdump"))


class _FakeGhidra:
    def __init__(self, *_: object, **__: object) -> None:
        pass

    async def analyze(self, *_args: object) -> ToolContribution:
        return ToolContribution(run=_tool_run("ghidra"))


class _FakeAngr:
    def __init__(self, *_: object, **__: object) -> None:
        pass

    async def analyze_targets(self, *_args: object) -> ToolContribution:
        return ToolContribution(run=_tool_run("angr"))


def _stub_tools(entrypoint: Any, monkeypatch: Any) -> None:
    monkeypatch.setattr(entrypoint, "DetectItEasyAdapter", _FakeDie)
    monkeypatch.setattr(entrypoint, "UpxAdapter", _FakeUpx)
    monkeypatch.setattr(entrypoint, "ObjdumpAdapter", _FakeObjdump)
    monkeypatch.setattr(entrypoint, "GhidraHeadlessAdapter", _FakeGhidra)
    monkeypatch.setattr(entrypoint, "AngrAdapter", _FakeAngr)


def _facts_args(sample: Path, output_dir: Path) -> argparse.Namespace:
    """The arguments the facts profile passes, minus the unpacking-only ones."""
    return argparse.Namespace(
        mode="facts",
        input=sample,
        output_dir=output_dir,
        max_functions=20_000,
        max_instructions=200_000,
        max_pseudocode_functions=20_000,
        target_addresses="",
        angr_enabled=False,
        command_timeout=None,
        skip_disassembly=False,
    )


async def _run_facts(entrypoint: Any, args: argparse.Namespace, sample: Path) -> int:
    limits = BinaryAnalysisLimits()
    metadata = inspect_binary(sample, limits)

    async def _prepare(args_: argparse.Namespace) -> tuple[object, ...]:
        # The real `_prepare` also materialises the output dir, copies the
        # sample onto the writable work tmpfs and inspects it there; the stub
        # only has to keep the output dir, since the sample is already real.
        args_.output_dir.mkdir(parents=True, exist_ok=True)
        return sample, metadata, limits, asyncio.Event()

    entrypoint._prepare = _prepare
    return int(await entrypoint._facts_mode(args))


def test_facts_document_carries_extracted_strings(tmp_path: Path, monkeypatch: Any) -> None:
    """Regression: the strings consumer must survive `StringExtraction`.

    Before the fix this raised `TypeError: 'StringExtraction' object is not
    iterable` while building the document, so no facts document was written.
    """
    entrypoint = _load_entrypoint()
    _stub_tools(entrypoint, monkeypatch)
    sample = tmp_path / "sample.elf"
    sample.write_bytes(elf64_sample())
    output_dir = tmp_path / "out"

    exit_code = asyncio.run(_run_facts(entrypoint, _facts_args(sample, output_dir), sample))

    assert exit_code == 0
    document = json.loads((output_dir / "binary-facts.json").read_text(encoding="utf-8"))
    strings = document["strings"]
    assert isinstance(strings, list)
    assert strings, "the sample carries section names long enough to be strings"
    # Each entry is a contract-shaped BinaryString, not a wrapper object.
    assert all(set(item) >= {"value", "encoding", "file_offset"} for item in strings)
    assert all(not isinstance(item, (list, tuple)) for item in strings)
    assert document["normalized_from"] == "objdump"


def test_facts_document_strings_match_the_extractor(tmp_path: Path, monkeypatch: Any) -> None:
    """The document's strings are exactly what `extract_strings` returns."""
    from vulnweaver_binary_analysis import extract_strings

    entrypoint = _load_entrypoint()
    _stub_tools(entrypoint, monkeypatch)
    sample = tmp_path / "sample.elf"
    sample.write_bytes(elf64_sample())
    output_dir = tmp_path / "out"

    exit_code = asyncio.run(_run_facts(entrypoint, _facts_args(sample, output_dir), sample))

    assert exit_code == 0
    document = json.loads((output_dir / "binary-facts.json").read_text(encoding="utf-8"))
    expected = extract_strings(sample, inspect_binary(sample), BinaryAnalysisLimits())
    assert [item["value"] for item in document["strings"]] == [
        item["value"] for item in expected.strings
    ]
