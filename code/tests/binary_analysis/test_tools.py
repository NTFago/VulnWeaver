from __future__ import annotations

import asyncio
import sys
from collections.abc import Sequence
from pathlib import Path

import pytest
from vulnweaver_binary_analysis import (
    AngrAdapter,
    BinaryAnalysisLimits,
    BoundedCommandRunner,
    DetectItEasyAdapter,
    GhidraHeadlessAdapter,
    ObjdumpAdapter,
    ToolCancelled,
    ToolOutputLimitExceeded,
    UpxAdapter,
    inspect_binary,
    parse_objdump_disassembly,
    parse_objdump_imports,
)
from vulnweaver_binary_analysis.tools import CommandResult

from tests.binary_analysis.samples import elf64_sample


class _RecordingRunner:
    def __init__(self) -> None:
        self.arguments: list[tuple[str, ...]] = []

    async def run(
        self,
        arguments: Sequence[str],
        *,
        timeout_seconds: float,
        max_output_bytes: int,
        cancellation: asyncio.Event,
        cwd: Path | None = None,
    ) -> CommandResult:
        del timeout_seconds, max_output_bytes, cancellation, cwd
        command = tuple(arguments)
        self.arguments.append(command)
        if "--version" in command:
            return CommandResult(0, b"GNU objdump 2.42\n", b"")
        if "-d" in command and command[0] == "objdump":
            return CommandResult(
                0,
                b"0000000000401000 <main>:\n  401000: 55  push %rbp\n",
                b"",
            )
        if "-t" in command and command[0] == "objdump":
            return CommandResult(0, b"", b"")
        if "-p" in command:
            return CommandResult(0, b"  NEEDED libc.so.6\n", b"")
        if command[0] == "diec":
            return CommandResult(0, b"Compiler: GCC\nPacker: UPX\n", b"")
        if command[:2] == ("upx", "-t"):
            return CommandResult(0, b"Packed 1 file.\n", b"")
        if command[:3] == ("upx", "-d", "-o"):
            Path(command[3]).write_bytes(elf64_sample())
            return CommandResult(0, b"Unpacked 1 file.\n", b"")
        raise AssertionError(f"unexpected command: {command}")


def test_objdump_output_is_normalized_with_file_offsets(tmp_path: Path) -> None:
    sample = tmp_path / "sample.elf"
    sample.write_bytes(elf64_sample())
    metadata = inspect_binary(sample)
    output = """
0000000000401000 <main>:
  401000: 55                    push   %rbp
  401001: 48 89 e5              mov    %rsp,%rbp
  401004: c3                    ret
0000000000401005 <helper>:
  401005: 90                    nop
"""
    functions, instructions = parse_objdump_disassembly(output, metadata, BinaryAnalysisLimits())
    assert [item["name"] for item in functions] == ["main", "helper"]
    assert instructions[1]["bytes"] == "4889e5"
    assert instructions[1]["file_offset"] == 0x201
    assert instructions[-1]["function_name"] == "helper"


def test_objdump_imports_cover_elf_needed_and_pe_dll_entries(tmp_path: Path) -> None:
    sample = tmp_path / "sample.elf"
    sample.write_bytes(elf64_sample())
    metadata = inspect_binary(sample)
    imports = parse_objdump_imports(
        """
  NEEDED               libc.so.6
    DLL Name: KERNEL32.dll
    000000000000  0012  CreateFileW
""",
        metadata,
    )
    assert imports[0]["library"] == "libc.so.6"
    assert imports[1]["library"] == "KERNEL32.dll"
    assert imports[1]["name"] == "CreateFileW"
    assert imports[1]["ordinal"] == 0x12


def test_objdump_and_die_adapters_use_fixed_arguments_and_merge_facts(
    tmp_path: Path,
) -> None:
    sample = tmp_path / "sample.elf"
    sample.write_bytes(elf64_sample())
    metadata = inspect_binary(sample)
    runner = _RecordingRunner()

    async def scenario() -> None:
        objdump = await ObjdumpAdapter(runner=runner).analyze(
            sample, metadata, BinaryAnalysisLimits(), asyncio.Event()
        )
        die = await DetectItEasyAdapter(runner=runner).analyze(
            sample, metadata, BinaryAnalysisLimits(), asyncio.Event()
        )
        assert objdump.run["status"] == "succeeded"
        assert objdump.functions[0]["name"] == "main"
        assert objdump.imports[0]["library"] == "libc.so.6"
        assert die.compiler == "Compiler: GCC"
        assert die.packer == "UPX"

    asyncio.run(scenario())
    assert all("-c" not in command and "--command" not in command for command in runner.arguments)


def test_upx_adapter_writes_only_the_caller_owned_destination(tmp_path: Path) -> None:
    source = tmp_path / "packed.elf"
    destination = tmp_path / "unpacked.elf"
    source.write_bytes(elf64_sample(upx_section=True))
    runner = _RecordingRunner()

    outcome = asyncio.run(
        UpxAdapter(runner=runner).unpack(
            source, destination, BinaryAnalysisLimits(), asyncio.Event()
        )
    )

    assert outcome.packed is True
    assert outcome.unpacked_path == destination
    assert inspect_binary(destination).format == "elf"
    assert runner.arguments[-1] == (
        "upx",
        "-d",
        "-o",
        str(destination),
        str(source),
    )


def test_unconfigured_heavy_adapters_are_explicitly_unavailable(tmp_path: Path) -> None:
    sample = tmp_path / "sample.elf"
    sample.write_bytes(elf64_sample())
    metadata = inspect_binary(sample)

    async def scenario() -> None:
        ghidra = await GhidraHeadlessAdapter(None, None).analyze(
            sample, metadata, BinaryAnalysisLimits(), asyncio.Event()
        )
        angr = await AngrAdapter(enabled=False).analyze(
            sample, metadata, BinaryAnalysisLimits(), asyncio.Event()
        )
        assert ghidra.run["status"] == "unavailable"
        assert ghidra.run["reason"] == "not_configured"
        assert angr.run["status"] == "unavailable"
        assert angr.run["reason"] == "not_configured"

    asyncio.run(scenario())


def test_bounded_command_runner_stops_output_floods() -> None:
    async def scenario() -> None:
        with pytest.raises(ToolOutputLimitExceeded):
            await BoundedCommandRunner().run(
                (sys.executable, "-c", "print('x' * 10000)"),
                timeout_seconds=10,
                max_output_bytes=128,
                cancellation=asyncio.Event(),
            )

    asyncio.run(scenario())


def test_bounded_command_runner_honors_cancellation() -> None:
    async def scenario() -> None:
        cancellation = asyncio.Event()
        cancellation.set()
        with pytest.raises(ToolCancelled):
            await BoundedCommandRunner().run(
                (sys.executable, "-c", "import time; time.sleep(30)"),
                timeout_seconds=10,
                max_output_bytes=128,
                cancellation=cancellation,
            )

    asyncio.run(scenario())
