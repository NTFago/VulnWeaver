from __future__ import annotations

import asyncio
import json
import sys
from collections.abc import Coroutine, Sequence
from pathlib import Path, PurePath
from typing import Any

import pytest
import vulnweaver_binary_analysis.tools as binary_tools
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


def _run_subprocess_scenario(scenario: Coroutine[Any, Any, None]) -> None:
    if sys.platform != "win32":
        asyncio.run(scenario)
        return
    policy_type = getattr(asyncio, "WindowsProactorEventLoopPolicy")  # noqa: B009
    loop = policy_type().new_event_loop()
    try:
        loop.run_until_complete(scenario)
    finally:
        loop.close()


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
                (
                    b"0000000000401000 <main>:\n"
                    b"  401000: e8 01 00 00 00  call 401006 <helper>\n"
                    b"  401005: c3  ret\n"
                    b"0000000000401006 <helper>:\n"
                    b"  401006: c3  ret\n"
                ),
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


class _GhidraRunner:
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
        script_index = command.index("ExportVulnWeaver.java")
        output = Path(command[script_index + 1])
        output.write_text(
            json.dumps(
                {
                    "functions": [
                        {
                            "name": "main",
                            "address": 0x401000,
                            "size": 7,
                            "attributes": {"source": "ghidra"},
                        }
                    ],
                    "instructions": [
                        {
                            "address": 0x401000,
                            "bytes": "e801000000",
                            "mnemonic": "CALL",
                            "operands": "401006 <helper>",
                            "function_name": "main",
                        },
                        {
                            "address": 0x401005,
                            "bytes": "c3",
                            "mnemonic": "RET",
                            "operands": "",
                            "function_name": "main",
                        },
                    ],
                    "basic_blocks": [],
                    "xrefs": [],
                    "pseudocode": [
                        {
                            "function_name": "main",
                            "address": 0x401000,
                            "text": "int main(void) { return helper(); }",
                            "tool_name": "ghidra",
                        }
                    ],
                    "symbolic_facts": [],
                    "imports": [],
                }
            ),
            encoding="utf-8",
        )
        return CommandResult(0, b"headless complete", b"")


class _AngrRunner:
    def __init__(self) -> None:
        self.target_argument = ""

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
        output = Path(command[4])
        self.target_argument = command[-1]
        targets = [int(value) for value in self.target_argument.split(",") if value]
        output.write_text(
            json.dumps(
                {
                    "functions": [],
                    "instructions": [],
                    "basic_blocks": [],
                    "xrefs": [],
                    "pseudocode": [],
                    "symbolic_facts": [
                        {
                            "function_address": address,
                            "status": "partial",
                            "steps": 32,
                            "explored_states": 32,
                            "reached_addresses": [address],
                            "unconstrained_states": 0,
                            "reason": "state_or_step_limit",
                        }
                        for address in targets
                    ],
                    "imports": [],
                }
            ),
            encoding="utf-8",
        )
        return CommandResult(0, b"angr complete", b"")


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
        assert len(objdump.basic_blocks) == 2
        assert objdump.xrefs[0]["type"] == "call"
        assert objdump.xrefs[0]["target_symbol"] == "helper"
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


def test_ghidra_structured_export_preserves_pseudocode_and_derives_cfg(
    tmp_path: Path,
) -> None:
    sample = tmp_path / "sample.elf"
    sample.write_bytes(elf64_sample())
    metadata = inspect_binary(sample)
    scripts = tmp_path / "scripts"
    scripts.mkdir()

    contribution = asyncio.run(
        GhidraHeadlessAdapter("analyzeHeadless", scripts, runner=_GhidraRunner()).analyze(
            sample, metadata, BinaryAnalysisLimits(), asyncio.Event()
        )
    )

    assert contribution.run["status"] == "succeeded"
    assert contribution.pseudocode[0]["function_name"] == "main"
    assert contribution.pseudocode[0]["tool_name"] == "ghidra"
    assert contribution.basic_blocks[0]["start_address"] == 0x401000
    assert contribution.xrefs[0]["target_address"] == 0x401006
    assert contribution.xrefs[0]["type"] == "call"


def test_angr_adapter_forwards_validated_targets_and_parses_symbolic_facts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sample = tmp_path / "sample.elf"
    sample.write_bytes(elf64_sample())
    metadata = inspect_binary(sample)
    runner = _AngrRunner()
    monkeypatch.setattr(binary_tools.importlib.util, "find_spec", lambda name: object())

    contribution = asyncio.run(
        AngrAdapter(enabled=True, runner=runner).analyze_targets(
            sample,
            metadata,
            BinaryAnalysisLimits(),
            asyncio.Event(),
            (0x401000,),
        )
    )

    assert runner.target_argument == str(0x401000)
    assert contribution.run["status"] == "succeeded"
    assert contribution.symbolic_facts[0]["function_address"] == 0x401000
    assert contribution.symbolic_facts[0]["status"] == "partial"
    assert contribution.symbolic_facts[0]["reason"] == "state_or_step_limit"


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

    _run_subprocess_scenario(scenario())


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

    _run_subprocess_scenario(scenario())


def test_bounded_command_runner_terminates_process_on_parent_cancellation() -> None:
    async def scenario() -> None:
        task = asyncio.create_task(
            BoundedCommandRunner().run(
                (sys.executable, "-c", "import time; time.sleep(30)"),
                timeout_seconds=60,
                max_output_bytes=128,
                cancellation=asyncio.Event(),
            )
        )
        await asyncio.sleep(0.1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    _run_subprocess_scenario(scenario())


def test_command_profile_omits_empty_target_addresses() -> None:
    from vulnweaver_binary_analysis.profiles import binary_command_profile

    profile = binary_command_profile(
        "vulnweaver-binary-tools:fixed", "sha256:" + "a" * 64
    )
    argv = profile.build_argv(
        {
            "max_functions": 100,
            "max_instructions": 1000,
            "max_pseudocode_functions": 50,
            "target_addresses": [],
            "angr_enabled": False,
        },
        PurePath("/input/sample"),
        PurePath("/output"),
    )
    assert "" not in argv
    assert "--target-addresses" not in argv

    argv_with_targets = profile.build_argv(
        {
            "max_functions": 100,
            "max_instructions": 1000,
            "max_pseudocode_functions": 50,
            "target_addresses": [4144],
            "angr_enabled": True,
        },
        PurePath("/input/sample"),
        PurePath("/output"),
    )
    assert argv_with_targets[argv_with_targets.index("--target-addresses") + 1] == "4144"
    assert "--angr-enabled" in argv_with_targets
