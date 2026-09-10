"""Fixed-command, no-shell adapters for binary reverse-engineering tools."""

from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import re
import shutil
import sys
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, cast

from vulnweaver_contracts import (
    BinaryBasicBlock,
    BinaryFunction,
    BinaryImport,
    BinaryInstruction,
    BinaryPseudocode,
    BinarySymbolicFact,
    BinarySymbolicStatus,
    BinaryToolRun,
    BinaryXref,
    BinaryXrefType,
    JsonObject,
    SandboxRequest,
    SandboxResult,
    SchemaVersion,
    StaticToolStatus,
)

from vulnweaver_binary_analysis.types import (
    BinaryAnalysisLimits,
    BinaryMetadata,
    ToolContribution,
    UpxOutcome,
)

_FUNCTION_HEADER = re.compile(r"^\s*([0-9a-fA-F]+)\s+<(.+)>:\s*$")
_INSTRUCTION = re.compile(
    r"^\s*([0-9a-fA-F]+):\s+((?:[0-9a-fA-F]{2}\s+)+)\s*([.A-Za-z][\w.]*)\s*(.*)$"
)
_SYMBOL = re.compile(
    r"^\s*([0-9a-fA-F]+)\s+([lg! ][w ][C ][W ][Ii ][dD ][FfO ])\s+([^\s]+)\s+([0-9a-fA-F]+)\s+(.+)$"
)
_DLL_NAME = re.compile(r"^\s*DLL Name:\s*(.+?)\s*$", re.IGNORECASE)
_PE_IMPORT = re.compile(r"^\s*[0-9a-fA-F]+\s+([0-9a-fA-F]+)\s+(.+?)\s*$")
_NEEDED = re.compile(r"^\s*NEEDED\s+(.+?)\s*$")
_DIRECT_TARGET = re.compile(r"^\s*(?:0x)?([0-9a-fA-F]+)(?:\s+<([^>]+)>)?")
_COMMENT_TARGET = re.compile(r"#\s*(?:0x)?([0-9a-fA-F]+)(?:\s+<([^>]+)>)?")


class BinaryToolAdapter(Protocol):
    name: str

    async def analyze(
        self,
        path: Path,
        metadata: BinaryMetadata,
        limits: BinaryAnalysisLimits,
        cancellation: asyncio.Event,
    ) -> ToolContribution: ...


class ToolExecutionError(RuntimeError):
    """Raised when an isolated tool cannot produce its declared result."""


class UpxUnpacker(Protocol):
    async def unpack(
        self,
        path: Path,
        destination: Path,
        limits: BinaryAnalysisLimits,
        cancellation: asyncio.Event,
    ) -> UpxOutcome: ...


class BinaryFactsSandbox(Protocol):
    async def run(
        self, request: SandboxRequest, cancellation: asyncio.Event
    ) -> SandboxResult: ...


class BinaryFactsAdapter:
    """Adapt the isolated binary-tools result to the normal tool contribution."""

    name = "binary-facts"

    def __init__(self, sandbox: BinaryFactsSandbox, store, *, image_digest: str, input_ref: str):
        self._sandbox = sandbox
        self._store = store
        self._image_digest = image_digest
        self._input_ref = input_ref

    async def analyze(
        self,
        path: Path,
        metadata: BinaryMetadata,
        limits: BinaryAnalysisLimits,
        cancellation: asyncio.Event,
    ) -> ToolContribution:
        request = SandboxRequest(
            schema_version=SchemaVersion.VALUE_1_0_0,
            id=f"binary-facts:{self._input_ref}",
            tool_name="binary-facts",
            tool_version="1.0.0",
            image_digest=self._image_digest,
            artifact_kind=metadata.format,
            input_ref=self._input_ref,
            arguments={
                "max_functions": limits.max_functions,
                "max_instructions": limits.max_instructions,
                "max_pseudocode_functions": limits.max_pseudocode_functions,
            },
            output_file_names=["binary-facts.json"],
            resource_budget=_sandbox_budget(limits),
            timeout_seconds=min(600, max(1, int(limits.command_timeout_seconds))),
        )
        result = await self._sandbox.run(request, cancellation)
        if result["status"] != "succeeded":
            raise ToolExecutionError("binary-facts sandbox execution failed")
        output = next(
            (item for item in result["outputs"] if item["path"] == "binary-facts.json"), None
        )
        if output is None:
            raise ToolExecutionError("binary-facts output is missing")
        with self._store.open(output["object_ref"]) as stream:
            facts = json.load(stream)
        tools = facts.get("tools", {})
        objdump = tools.get("objdump", {})
        die = tools.get("die", {})
        fallback_run = {
            "tool_name": self.name,
            "tool_version": "1.0.0",
            "status": "succeeded",
            "exit_code": 0,
            "reason": None,
            "raw_output": None,
        }
        return ToolContribution(
            run=cast(BinaryToolRun, objdump.get("run", fallback_run)),
            functions=tuple(cast(list[BinaryFunction], facts.get("functions", []))),
            instructions=tuple(cast(list[BinaryInstruction], facts.get("instructions", []))),
            basic_blocks=tuple(cast(list[BinaryBasicBlock], facts.get("basic_blocks", []))),
            xrefs=tuple(cast(list[BinaryXref], facts.get("xrefs", []))),
            pseudocode=tuple(cast(list[BinaryPseudocode], facts.get("pseudocode", []))),
            compiler=cast(str | None, die.get("compiler")),
            packer=cast(str | None, die.get("packer")),
            packed=cast(bool | None, die.get("packed")),
        )


def _sandbox_budget(limits: BinaryAnalysisLimits) -> dict[str, object]:
    return {
        "max_model_tokens": 0,
        "cpu_millis": 4000,
        "memory_bytes": 3 * 1024 * 1024 * 1024,
        "disk_bytes": 1024 * 1024 * 1024,
        "max_tool_concurrency": 1,
        "max_dynamic_runs": 0,
        "timeout_seconds": min(600, int(limits.command_timeout_seconds)),
    }


@dataclass(frozen=True, slots=True)
class CommandResult:
    exit_code: int
    stdout: bytes
    stderr: bytes


@dataclass(slots=True)
class _OutputBudget:
    remaining: int
    lock: asyncio.Lock


class ToolUnavailable(FileNotFoundError):
    pass


class ToolOutputLimitExceeded(RuntimeError):
    pass


class ToolCancelled(RuntimeError):
    pass


class CommandRunner(Protocol):
    async def run(
        self,
        arguments: Sequence[str],
        *,
        timeout_seconds: float,
        max_output_bytes: int,
        cancellation: asyncio.Event,
        cwd: Path | None = None,
    ) -> CommandResult: ...


class BoundedCommandRunner:
    """Run one fixed argument vector without a shell and bound time/output."""

    async def run(
        self,
        arguments: Sequence[str],
        *,
        timeout_seconds: float,
        max_output_bytes: int,
        cancellation: asyncio.Event,
        cwd: Path | None = None,
    ) -> CommandResult:
        if not arguments:
            raise ValueError("command arguments cannot be empty")
        executable = shutil.which(arguments[0])
        if executable is None:
            raise ToolUnavailable(arguments[0])
        environment = {
            key: value
            for key in ("PATH", "LANG", "LC_ALL", "JAVA_HOME", "GHIDRA_HOME", "HOME", "TMPDIR")
            if (value := os.environ.get(key)) is not None
        }
        environment["LANG"] = "C"
        environment["LC_ALL"] = "C"
        process = await asyncio.create_subprocess_exec(
            executable,
            *arguments[1:],
            cwd=str(cwd) if cwd is not None else None,
            env=environment,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        communicate = asyncio.create_task(_bounded_communicate(process, max_output_bytes))
        cancelled = asyncio.create_task(cancellation.wait())
        try:
            done, _ = await asyncio.wait(
                {communicate, cancelled},
                timeout=timeout_seconds,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if not done:
                await _terminate(process)
                communicate.cancel()
                raise TimeoutError(f"tool exceeded {timeout_seconds:g} seconds")
            if cancelled in done and cancelled.result():
                await _terminate(process)
                communicate.cancel()
                raise ToolCancelled("tool execution was cancelled")
            try:
                stdout, stderr, exit_code = await communicate
            except ToolOutputLimitExceeded:
                await _terminate(process)
                raise
            return CommandResult(exit_code=exit_code, stdout=stdout, stderr=stderr)
        except asyncio.CancelledError:
            await _terminate(process)
            raise
        finally:
            cancelled.cancel()
            if not communicate.done():
                communicate.cancel()
            await asyncio.gather(cancelled, communicate, return_exceptions=True)


class ObjdumpAdapter:
    name = "objdump"

    def __init__(self, executable: str = "objdump", runner: CommandRunner | None = None) -> None:
        self._executable = executable
        self._runner = runner or BoundedCommandRunner()

    async def analyze(
        self,
        path: Path,
        metadata: BinaryMetadata,
        limits: BinaryAnalysisLimits,
        cancellation: asyncio.Event,
    ) -> ToolContribution:
        try:
            version_result = await self._run(("--version",), path, limits, cancellation)
            disassembly, symbols, private = await asyncio.gather(
                self._run(("-d", "-w", str(path)), path, limits, cancellation, include_path=False),
                self._run(("-t", str(path)), path, limits, cancellation, include_path=False),
                self._run(("-p", str(path)), path, limits, cancellation, include_path=False),
            )
        except ToolUnavailable:
            return ToolContribution(run=_unavailable_run(self.name, "executable_not_found"))
        except ToolCancelled:
            raise
        except TimeoutError:
            return ToolContribution(run=_failed_run(self.name, "timeout", None))
        except ToolOutputLimitExceeded:
            return ToolContribution(run=_failed_run(self.name, "output_limit_exceeded", None))
        version = _first_line(version_result.stdout)
        raw = _bounded_text(
            b"\n--- disassembly ---\n"
            + disassembly.stdout
            + b"\n--- symbols ---\n"
            + symbols.stdout
            + b"\n--- private ---\n"
            + private.stdout,
            limits.max_raw_output_chars,
        )
        exit_codes = (disassembly.exit_code, symbols.exit_code, private.exit_code)
        functions, instructions = parse_objdump_disassembly(
            disassembly.stdout.decode("utf-8", "replace"), metadata, limits
        )
        symbol_functions = parse_objdump_symbols(
            symbols.stdout.decode("utf-8", "replace"), metadata, limits
        )
        functions = _merge_functions(functions, symbol_functions, limits.max_functions)
        imports = parse_objdump_imports(private.stdout.decode("utf-8", "replace"), metadata)
        basic_blocks, xrefs = derive_objdump_control_flow(instructions, limits)
        if any(code != 0 for code in exit_codes):
            status = StaticToolStatus.FAILED
            reason = "one_or_more_objdump_views_failed"
        else:
            status = StaticToolStatus.SUCCEEDED
            reason = None
        return ToolContribution(
            run=BinaryToolRun(
                tool_name=self.name,
                tool_version=version,
                status=status,
                exit_code=max(exit_codes),
                reason=reason,
                raw_output=raw,
            ),
            functions=functions,
            instructions=instructions,
            basic_blocks=basic_blocks,
            xrefs=xrefs,
            imports=imports,
        )

    async def _run(
        self,
        suffix: Sequence[str],
        path: Path,
        limits: BinaryAnalysisLimits,
        cancellation: asyncio.Event,
        *,
        include_path: bool = True,
    ) -> CommandResult:
        arguments = (self._executable, *suffix)
        if include_path:
            arguments = (self._executable, *suffix)
        return await self._runner.run(
            arguments,
            timeout_seconds=limits.command_timeout_seconds,
            max_output_bytes=limits.max_tool_output_bytes,
            cancellation=cancellation,
            cwd=path.parent,
        )


class DetectItEasyAdapter:
    name = "die"

    def __init__(self, executable: str = "diec", runner: CommandRunner | None = None) -> None:
        self._executable = executable
        self._runner = runner or BoundedCommandRunner()

    async def analyze(
        self,
        path: Path,
        metadata: BinaryMetadata,
        limits: BinaryAnalysisLimits,
        cancellation: asyncio.Event,
    ) -> ToolContribution:
        del metadata
        try:
            result = await self._runner.run(
                (self._executable, str(path)),
                timeout_seconds=limits.command_timeout_seconds,
                max_output_bytes=limits.max_tool_output_bytes,
                cancellation=cancellation,
                cwd=path.parent,
            )
        except ToolUnavailable:
            return ToolContribution(run=_unavailable_run(self.name, "executable_not_found"))
        except ToolCancelled:
            raise
        except TimeoutError:
            return ToolContribution(run=_failed_run(self.name, "timeout", None))
        except ToolOutputLimitExceeded:
            return ToolContribution(run=_failed_run(self.name, "output_limit_exceeded", None))
        output = _bounded_text(result.stdout + b"\n" + result.stderr, limits.max_raw_output_chars)
        compiler, packer = _detect_compiler_and_packer(output)
        return ToolContribution(
            run=BinaryToolRun(
                tool_name=self.name,
                tool_version=None,
                status=(
                    StaticToolStatus.SUCCEEDED if result.exit_code == 0 else StaticToolStatus.FAILED
                ),
                exit_code=result.exit_code,
                reason=None if result.exit_code == 0 else "nonzero_exit",
                raw_output=output,
            ),
            compiler=compiler,
            packer=packer,
            packed=True if packer else None,
        )


class UpxAdapter:
    name = "upx"

    def __init__(self, executable: str = "upx", runner: CommandRunner | None = None) -> None:
        self._executable = executable
        self._runner = runner or BoundedCommandRunner()

    async def unpack(
        self,
        path: Path,
        destination: Path,
        limits: BinaryAnalysisLimits,
        cancellation: asyncio.Event,
    ) -> UpxOutcome:
        try:
            tested = await self._runner.run(
                (self._executable, "-t", str(path)),
                timeout_seconds=limits.command_timeout_seconds,
                max_output_bytes=limits.max_tool_output_bytes,
                cancellation=cancellation,
                cwd=path.parent,
            )
        except ToolUnavailable:
            return UpxOutcome(run=_unavailable_run(self.name, "executable_not_found"), packed=False)
        except ToolCancelled:
            raise
        except TimeoutError:
            return UpxOutcome(run=_failed_run(self.name, "test_timeout", None), packed=False)
        except ToolOutputLimitExceeded:
            return UpxOutcome(
                run=_failed_run(self.name, "test_output_limit_exceeded", None), packed=False
            )
        tested_text = _bounded_text(
            tested.stdout + b"\n" + tested.stderr, limits.max_raw_output_chars
        )
        if tested.exit_code != 0:
            lowered = tested_text.lower()
            not_packed = "notpackedexception" in lowered or "not packed" in lowered
            return UpxOutcome(
                run=BinaryToolRun(
                    tool_name=self.name,
                    tool_version=None,
                    status=(StaticToolStatus.SUCCEEDED if not_packed else StaticToolStatus.FAILED),
                    exit_code=tested.exit_code,
                    reason="not_upx_packed" if not_packed else "test_failed",
                    raw_output=tested_text,
                ),
                packed=False,
            )
        try:
            unpacked = await self._runner.run(
                (self._executable, "-d", "-o", str(destination), str(path)),
                timeout_seconds=limits.command_timeout_seconds,
                max_output_bytes=limits.max_tool_output_bytes,
                cancellation=cancellation,
                cwd=path.parent,
            )
        except TimeoutError:
            return UpxOutcome(
                run=_failed_run(self.name, "unpack_timeout", tested_text), packed=True
            )
        except ToolOutputLimitExceeded:
            return UpxOutcome(
                run=_failed_run(self.name, "unpack_output_limit_exceeded", tested_text), packed=True
            )
        raw = _bounded_text(
            tested.stdout
            + tested.stderr
            + b"\n--- unpack ---\n"
            + unpacked.stdout
            + unpacked.stderr,
            limits.max_raw_output_chars,
        )
        if unpacked.exit_code != 0 or not destination.is_file():
            return UpxOutcome(
                run=_failed_run(self.name, "unpack_failed", raw, unpacked.exit_code), packed=True
            )
        return UpxOutcome(
            run=BinaryToolRun(
                tool_name=self.name,
                tool_version=None,
                status=StaticToolStatus.SUCCEEDED,
                exit_code=0,
                reason="unpacked",
                raw_output=raw,
            ),
            packed=True,
            unpacked_path=destination,
        )


class GhidraHeadlessAdapter:
    name = "ghidra"

    def __init__(
        self,
        executable: str | None,
        script_directory: str | Path | None,
        runner: CommandRunner | None = None,
    ) -> None:
        self._executable = executable
        self._script_directory = Path(script_directory) if script_directory else None
        self._runner = runner or BoundedCommandRunner()

    async def analyze(
        self,
        path: Path,
        metadata: BinaryMetadata,
        limits: BinaryAnalysisLimits,
        cancellation: asyncio.Event,
    ) -> ToolContribution:
        if not self._executable or self._script_directory is None:
            return ToolContribution(run=_unavailable_run(self.name, "not_configured"))
        with tempfile.TemporaryDirectory(prefix="vulnweaver-ghidra-", dir=path.parent) as temporary:
            root = Path(temporary)
            # Ghidra refuses to create the project directory itself.
            (root / "project").mkdir()
            output = root / "vulnweaver-ghidra.json"
            try:
                result = await self._runner.run(
                    (
                        self._executable,
                        str(root / "project"),
                        "VulnWeaver",
                        "-import",
                        str(path),
                        "-scriptPath",
                        str(self._script_directory),
                        "-postScript",
                        "ExportVulnWeaver.java",
                        str(output),
                        str(limits.max_functions),
                        str(limits.max_instructions),
                        str(limits.max_pseudocode_functions),
                        str(limits.max_pseudocode_chars),
                        "-deleteProject",
                    ),
                    timeout_seconds=limits.command_timeout_seconds,
                    max_output_bytes=limits.max_tool_output_bytes,
                    cancellation=cancellation,
                    cwd=root,
                )
            except ToolUnavailable:
                return ToolContribution(run=_unavailable_run(self.name, "executable_not_found"))
            except ToolCancelled:
                raise
            except TimeoutError:
                return ToolContribution(run=_failed_run(self.name, "timeout", None))
            except ToolOutputLimitExceeded:
                return ToolContribution(run=_failed_run(self.name, "output_limit_exceeded", None))
            raw = _bounded_text(result.stdout + b"\n" + result.stderr, limits.max_raw_output_chars)
            if result.exit_code != 0 or not output.is_file():
                return ToolContribution(
                    run=_failed_run(self.name, "analysis_failed", raw, result.exit_code)
                )
            try:
                document = _load_json_file(output, limits.max_tool_output_bytes)
                (
                    functions,
                    instructions,
                    basic_blocks,
                    xrefs,
                    pseudocode,
                    symbolic_facts,
                    imports,
                ) = _parse_structured_output(document, metadata, limits)
            except (OSError, UnicodeError, json.JSONDecodeError, ValueError, TypeError):
                return ToolContribution(
                    run=_failed_run(self.name, "invalid_export", raw, result.exit_code)
                )
            return ToolContribution(
                run=BinaryToolRun(
                    tool_name=self.name,
                    tool_version=None,
                    status=StaticToolStatus.SUCCEEDED,
                    exit_code=0,
                    reason=None,
                    raw_output=raw,
                ),
                functions=functions,
                instructions=instructions,
                basic_blocks=basic_blocks,
                xrefs=xrefs,
                pseudocode=pseudocode,
                symbolic_facts=symbolic_facts,
                imports=imports,
            )


class AngrAdapter:
    name = "angr"

    def __init__(self, enabled: bool = False, runner: CommandRunner | None = None) -> None:
        self._enabled = enabled
        self._runner = runner or BoundedCommandRunner()

    async def analyze(
        self,
        path: Path,
        metadata: BinaryMetadata,
        limits: BinaryAnalysisLimits,
        cancellation: asyncio.Event,
    ) -> ToolContribution:
        return await self.analyze_targets(path, metadata, limits, cancellation, ())

    async def analyze_targets(
        self,
        path: Path,
        metadata: BinaryMetadata,
        limits: BinaryAnalysisLimits,
        cancellation: asyncio.Event,
        target_addresses: tuple[int, ...],
    ) -> ToolContribution:
        if not self._enabled:
            return ToolContribution(run=_unavailable_run(self.name, "not_configured"))
        if importlib.util.find_spec("angr") is None:
            return ToolContribution(run=_unavailable_run(self.name, "python_package_not_installed"))
        with tempfile.TemporaryDirectory(prefix="vulnweaver-angr-", dir=path.parent) as temporary:
            output = Path(temporary) / "angr.json"
            try:
                result = await self._runner.run(
                    (
                        sys.executable,
                        "-m",
                        "vulnweaver_binary_analysis.angr_helper",
                        str(path),
                        str(output),
                        str(limits.max_functions),
                        str(limits.max_instructions),
                        str(limits.max_basic_blocks),
                        str(limits.max_xrefs),
                        str(limits.max_symbolic_steps),
                        str(limits.max_symbolic_states),
                        ",".join(str(value) for value in target_addresses),
                    ),
                    timeout_seconds=limits.command_timeout_seconds,
                    max_output_bytes=limits.max_tool_output_bytes,
                    cancellation=cancellation,
                    cwd=path.parent,
                )
            except ToolUnavailable:
                return ToolContribution(run=_unavailable_run(self.name, "python_not_found"))
            except ToolCancelled:
                raise
            except TimeoutError:
                return ToolContribution(run=_failed_run(self.name, "timeout", None))
            except ToolOutputLimitExceeded:
                return ToolContribution(run=_failed_run(self.name, "output_limit_exceeded", None))
            raw = _bounded_text(result.stdout + b"\n" + result.stderr, limits.max_raw_output_chars)
            if result.exit_code != 0 or not output.is_file():
                return ToolContribution(
                    run=_failed_run(self.name, "analysis_failed", raw, result.exit_code)
                )
            try:
                document = _load_json_file(output, limits.max_tool_output_bytes)
                (
                    functions,
                    instructions,
                    basic_blocks,
                    xrefs,
                    pseudocode,
                    symbolic_facts,
                    imports,
                ) = _parse_structured_output(document, metadata, limits)
            except (OSError, UnicodeError, json.JSONDecodeError, ValueError, TypeError):
                return ToolContribution(
                    run=_failed_run(self.name, "invalid_export", raw, result.exit_code)
                )
            return ToolContribution(
                run=BinaryToolRun(
                    tool_name=self.name,
                    tool_version=None,
                    status=StaticToolStatus.SUCCEEDED,
                    exit_code=0,
                    reason=None,
                    raw_output=raw,
                ),
                functions=functions,
                instructions=instructions,
                basic_blocks=basic_blocks,
                xrefs=xrefs,
                pseudocode=pseudocode,
                symbolic_facts=symbolic_facts,
                imports=imports,
            )


def parse_objdump_disassembly(
    output: str, metadata: BinaryMetadata, limits: BinaryAnalysisLimits
) -> tuple[tuple[BinaryFunction, ...], tuple[BinaryInstruction, ...]]:
    functions: list[BinaryFunction] = []
    instructions: list[BinaryInstruction] = []
    current_name: str | None = None
    current_address: int | None = None
    for line in output.splitlines():
        header = _FUNCTION_HEADER.match(line)
        if header:
            if current_name is not None and current_address is not None:
                size = max(0, int(header.group(1), 16) - current_address)
                functions.append(
                    _function(current_name, current_address, size, metadata, "objdump")
                )
                if len(functions) >= limits.max_functions:
                    break
            current_address = int(header.group(1), 16)
            current_name = header.group(2)[:4096]
            continue
        instruction = _INSTRUCTION.match(line)
        if instruction and len(instructions) < limits.max_instructions:
            address = int(instruction.group(1), 16)
            byte_string = "".join(instruction.group(2).split()).lower()[:128]
            instructions.append(
                BinaryInstruction(
                    address=address,
                    file_offset=metadata.virtual_address_to_offset(address),
                    bytes=byte_string,
                    mnemonic=instruction.group(3)[:128],
                    operands=instruction.group(4)[:4096],
                    function_name=current_name,
                )
            )
    if (
        current_name is not None
        and current_address is not None
        and len(functions) < limits.max_functions
    ):
        last_address = instructions[-1]["address"] + 1 if instructions else current_address
        functions.append(
            _function(
                current_name,
                current_address,
                max(0, last_address - current_address),
                metadata,
                "objdump",
            )
        )
    return tuple(functions), tuple(instructions)


def derive_objdump_control_flow(
    instructions: tuple[BinaryInstruction, ...],
    limits: BinaryAnalysisLimits,
) -> tuple[tuple[BinaryBasicBlock, ...], tuple[BinaryXref, ...]]:
    by_function: dict[str | None, list[BinaryInstruction]] = {}
    xrefs: list[BinaryXref] = []
    xref_keys: set[tuple[int, int, BinaryXrefType]] = set()
    for instruction in instructions:
        by_function.setdefault(instruction["function_name"], []).append(instruction)
        mnemonic = instruction["mnemonic"].lower()
        reference_type: BinaryXrefType | None = None
        if mnemonic.startswith("call"):
            reference_type = BinaryXrefType.CALL
        elif mnemonic.startswith("j"):
            reference_type = BinaryXrefType.JUMP
        if reference_type is not None:
            target = _reference(_DIRECT_TARGET, instruction["operands"])
            if target is not None:
                _append_xref(xrefs, xref_keys, instruction, target, reference_type, limits)
        data_target = _reference(_COMMENT_TARGET, instruction["operands"])
        if data_target is not None:
            _append_xref(
                xrefs,
                xref_keys,
                instruction,
                data_target,
                BinaryXrefType.DATA,
                limits,
            )

    blocks: list[BinaryBasicBlock] = []
    for function_name, function_instructions in by_function.items():
        ordered = sorted(function_instructions, key=lambda item: item["address"])
        if not ordered:
            continue
        address_indexes = {item["address"]: index for index, item in enumerate(ordered)}
        leaders = {ordered[0]["address"]}
        for index, instruction in enumerate(ordered):
            mnemonic = instruction["mnemonic"].lower()
            if mnemonic.startswith("j"):
                target = _reference(_DIRECT_TARGET, instruction["operands"])
                if target is not None and target[0] in address_indexes:
                    leaders.add(target[0])
            if (mnemonic.startswith("j") or mnemonic.startswith("ret")) and index + 1 < len(
                ordered
            ):
                leaders.add(ordered[index + 1]["address"])
        leader_indexes = sorted(address_indexes[address] for address in leaders)
        for position, start_index in enumerate(leader_indexes):
            if len(blocks) >= limits.max_basic_blocks:
                break
            stop_index = (
                leader_indexes[position + 1] if position + 1 < len(leader_indexes) else len(ordered)
            )
            block_instructions = ordered[start_index:stop_index]
            if not block_instructions:
                continue
            last = block_instructions[-1]
            successors = _block_successors(
                last,
                ordered,
                stop_index,
            )
            blocks.append(
                BinaryBasicBlock(
                    function_name=function_name,
                    start_address=block_instructions[0]["address"],
                    end_address=_instruction_end(last),
                    successor_addresses=successors,
                )
            )
    return tuple(blocks), tuple(xrefs)


def _block_successors(
    last: BinaryInstruction,
    ordered: list[BinaryInstruction],
    next_index: int,
) -> list[int]:
    mnemonic = last["mnemonic"].lower()
    fallthrough = ordered[next_index]["address"] if next_index < len(ordered) else None
    target = _reference(_DIRECT_TARGET, last["operands"])
    if mnemonic.startswith("ret"):
        return []
    if mnemonic in {"jmp", "jmpq", "ljmp"}:
        return [target[0]] if target is not None else []
    if mnemonic.startswith("j"):
        values: set[int] = set()
        if target is not None:
            values.add(target[0])
        if fallthrough is not None:
            values.add(fallthrough)
        return sorted(values)
    return [fallthrough] if fallthrough is not None else []


def _append_xref(
    output: list[BinaryXref],
    keys: set[tuple[int, int, BinaryXrefType]],
    instruction: BinaryInstruction,
    target: tuple[int, str | None],
    reference_type: BinaryXrefType,
    limits: BinaryAnalysisLimits,
) -> None:
    key = (instruction["address"], target[0], reference_type)
    if key in keys or len(output) >= limits.max_xrefs:
        return
    output.append(
        BinaryXref(
            source_address=instruction["address"],
            target_address=target[0],
            type=reference_type,
            source_function=instruction["function_name"],
            target_symbol=target[1],
        )
    )
    keys.add(key)


def _reference(pattern: re.Pattern[str], operands: str) -> tuple[int, str | None] | None:
    matched = pattern.search(operands)
    if matched is None:
        return None
    return int(matched.group(1), 16), matched.group(2)[:4096] if matched.group(2) else None


def _instruction_end(instruction: BinaryInstruction) -> int:
    size = max(1, len(instruction["bytes"]) // 2)
    return instruction["address"] + size


def parse_objdump_symbols(
    output: str, metadata: BinaryMetadata, limits: BinaryAnalysisLimits
) -> tuple[BinaryFunction, ...]:
    functions: list[BinaryFunction] = []
    for line in output.splitlines():
        matched = _SYMBOL.match(line)
        if matched is None:
            continue
        flags = matched.group(2)
        if "F" not in flags.upper():
            continue
        address = int(matched.group(1), 16)
        size = int(matched.group(4), 16)
        name = matched.group(5).strip()[:4096]
        if name:
            functions.append(_function(name, address, size, metadata, "symbol-table"))
        if len(functions) >= limits.max_functions:
            break
    return tuple(functions)


def parse_objdump_imports(output: str, metadata: BinaryMetadata) -> tuple[BinaryImport, ...]:
    imports: list[BinaryImport] = []
    current_library: str | None = None
    for line in output.splitlines():
        needed = _NEEDED.match(line)
        if needed:
            imports.append(
                BinaryImport(library=needed.group(1)[:4096], name=None, ordinal=None, address=None)
            )
            continue
        dll = _DLL_NAME.match(line)
        if dll:
            current_library = dll.group(1)[:4096]
            continue
        if current_library:
            item = _PE_IMPORT.match(line)
            if item:
                hint = int(item.group(1), 16)
                name = item.group(2).strip()[:4096]
                if name and not name.startswith("Table"):
                    imports.append(
                        BinaryImport(
                            library=current_library,
                            name=name,
                            ordinal=hint,
                            address=None,
                        )
                    )
    del metadata
    return tuple(imports)


def _parse_structured_output(
    document: object,
    metadata: BinaryMetadata,
    limits: BinaryAnalysisLimits,
) -> tuple[
    tuple[BinaryFunction, ...],
    tuple[BinaryInstruction, ...],
    tuple[BinaryBasicBlock, ...],
    tuple[BinaryXref, ...],
    tuple[BinaryPseudocode, ...],
    tuple[BinarySymbolicFact, ...],
    tuple[BinaryImport, ...],
]:
    if not isinstance(document, Mapping):
        raise ValueError("tool export must be an object")
    mapping = cast(Mapping[str, object], document)
    functions: list[BinaryFunction] = []
    for item in _object_list(mapping.get("functions"))[: limits.max_functions]:
        address = _nonnegative_int(item.get("address"))
        name = str(item.get("name") or f"sub_{address:x}")[:4096]
        size = _nonnegative_int(item.get("size"), default=0)
        attributes_value = item.get("attributes")
        attributes: Mapping[str, object] = (
            cast(Mapping[str, object], attributes_value)
            if isinstance(attributes_value, Mapping)
            else {}
        )
        functions.append(
            BinaryFunction(
                name=name,
                address=address,
                size=size,
                file_offset=metadata.virtual_address_to_offset(address),
                attributes=cast(JsonObject, dict(attributes)),
            )
        )
    instructions: list[BinaryInstruction] = []
    for item in _object_list(mapping.get("instructions"))[: limits.max_instructions]:
        address = _nonnegative_int(item.get("address"))
        instructions.append(
            BinaryInstruction(
                address=address,
                file_offset=metadata.virtual_address_to_offset(address),
                bytes=str(item.get("bytes") or "").lower()[:128],
                mnemonic=str(item.get("mnemonic") or "unknown")[:128],
                operands=str(item.get("operands") or "")[:4096],
                function_name=(
                    str(item["function_name"])[:4096] if item.get("function_name") else None
                ),
            )
        )
    basic_blocks: list[BinaryBasicBlock] = []
    for item in _object_list(mapping.get("basic_blocks"))[: limits.max_basic_blocks]:
        basic_blocks.append(
            BinaryBasicBlock(
                function_name=(
                    str(item["function_name"])[:4096] if item.get("function_name") else None
                ),
                start_address=_nonnegative_int(item.get("start_address")),
                end_address=_nonnegative_int(item.get("end_address")),
                successor_addresses=_nonnegative_int_list(item.get("successor_addresses")),
            )
        )
    xrefs: list[BinaryXref] = []
    for item in _object_list(mapping.get("xrefs"))[: limits.max_xrefs]:
        xrefs.append(
            BinaryXref(
                source_address=_nonnegative_int(item.get("source_address")),
                target_address=_nonnegative_int(item.get("target_address")),
                type=BinaryXrefType(str(item.get("type"))),
                source_function=(
                    str(item["source_function"])[:4096] if item.get("source_function") else None
                ),
                target_symbol=(
                    str(item["target_symbol"])[:4096] if item.get("target_symbol") else None
                ),
            )
        )
    derived_blocks, derived_xrefs = derive_objdump_control_flow(tuple(instructions), limits)
    if not basic_blocks:
        basic_blocks.extend(derived_blocks)
    if not xrefs:
        xrefs.extend(derived_xrefs)
    pseudocode: list[BinaryPseudocode] = []
    for item in _object_list(mapping.get("pseudocode"))[: limits.max_pseudocode_functions]:
        body = str(item.get("text") or "")[: limits.max_pseudocode_chars]
        if not body:
            continue
        pseudocode.append(
            BinaryPseudocode(
                function_name=str(item.get("function_name") or "unknown")[:4096],
                address=_nonnegative_int(item.get("address")),
                text=body,
                tool_name=str(item.get("tool_name") or "unknown")[:128],
            )
        )
    symbolic_facts: list[BinarySymbolicFact] = []
    for item in _object_list(mapping.get("symbolic_facts"))[: limits.max_symbolic_functions]:
        symbolic_facts.append(
            BinarySymbolicFact(
                function_address=_nonnegative_int(item.get("function_address")),
                status=BinarySymbolicStatus(str(item.get("status"))),
                steps=_nonnegative_int(item.get("steps")),
                explored_states=_nonnegative_int(item.get("explored_states")),
                reached_addresses=_nonnegative_int_list(item.get("reached_addresses")),
                unconstrained_states=_nonnegative_int(item.get("unconstrained_states")),
                reason=str(item["reason"])[:4096] if item.get("reason") else None,
            )
        )
    imports: list[BinaryImport] = []
    for item in _object_list(mapping.get("imports"))[: limits.max_functions]:
        imports.append(
            BinaryImport(
                library=str(item["library"])[:4096] if item.get("library") else None,
                name=str(item["name"])[:4096] if item.get("name") else None,
                ordinal=_optional_nonnegative_int(item.get("ordinal")),
                address=_optional_nonnegative_int(item.get("address")),
            )
        )
    return (
        tuple(functions),
        tuple(instructions),
        tuple(basic_blocks),
        tuple(xrefs),
        tuple(pseudocode),
        tuple(symbolic_facts),
        tuple(imports),
    )


def _object_list(value: object) -> list[Mapping[str, object]]:
    if not isinstance(value, list):
        return []
    items = cast(list[object], value)
    return [cast(Mapping[str, object], item) for item in items if isinstance(item, Mapping)]


def _nonnegative_int(value: object, *, default: int | None = None) -> int:
    if value is None and default is not None:
        return default
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("expected a non-negative integer")
    return value


def _nonnegative_int_list(value: object) -> list[int]:
    if not isinstance(value, list):
        return []
    items = cast(list[object], value)
    return sorted({_nonnegative_int(item) for item in items})


def _optional_nonnegative_int(value: object) -> int | None:
    return None if value is None else _nonnegative_int(value)


def _function(
    name: str, address: int, size: int, metadata: BinaryMetadata, source: str
) -> BinaryFunction:
    return BinaryFunction(
        name=name[:4096],
        address=address,
        size=size,
        file_offset=metadata.virtual_address_to_offset(address),
        attributes={"source": source},
    )


def _merge_functions(
    first: tuple[BinaryFunction, ...], second: tuple[BinaryFunction, ...], limit: int
) -> tuple[BinaryFunction, ...]:
    merged: dict[tuple[int, str], BinaryFunction] = {}
    for item in (*first, *second):
        merged.setdefault((item["address"], item["name"]), item)
        if len(merged) >= limit:
            break
    return tuple(sorted(merged.values(), key=lambda item: (item["address"], item["name"])))


def _load_json_file(path: Path, max_bytes: int) -> object:
    size = path.stat().st_size
    if size > max_bytes:
        raise ValueError("structured tool export exceeds the configured limit")
    return json.loads(path.read_text(encoding="utf-8"))


def _detect_compiler_and_packer(output: str) -> tuple[str | None, str | None]:
    compiler: str | None = None
    packer: str | None = None
    for line in output.splitlines():
        lowered = line.lower()
        if compiler is None and any(
            token in lowered for token in ("gcc", "clang", "msvc", "mingw")
        ):
            compiler = line.strip()[:4096]
        if packer is None and "upx" in lowered:
            packer = "UPX"
    return compiler, packer


def _first_line(value: bytes) -> str | None:
    text = value.decode("utf-8", "replace").splitlines()
    return text[0][:128] if text else None


def _bounded_text(value: bytes, limit: int) -> str:
    return value[:limit].decode("utf-8", "replace")


def _unavailable_run(name: str, reason: str) -> BinaryToolRun:
    return BinaryToolRun(
        tool_name=name,
        tool_version=None,
        status=StaticToolStatus.UNAVAILABLE,
        exit_code=None,
        reason=reason,
        raw_output=None,
    )


def _failed_run(
    name: str, reason: str, raw_output: str | None, exit_code: int | None = None
) -> BinaryToolRun:
    return BinaryToolRun(
        tool_name=name,
        tool_version=None,
        status=StaticToolStatus.FAILED,
        exit_code=exit_code,
        reason=reason,
        raw_output=raw_output,
    )


async def _bounded_communicate(
    process: asyncio.subprocess.Process, max_output_bytes: int
) -> tuple[bytes, bytes, int]:
    if process.stdout is None or process.stderr is None:
        raise RuntimeError("tool pipes were not configured")
    budget = _OutputBudget(remaining=max_output_bytes, lock=asyncio.Lock())
    stdout_task = asyncio.create_task(_read_bounded(process.stdout, budget))
    stderr_task = asyncio.create_task(_read_bounded(process.stderr, budget))
    try:
        stdout, stderr, exit_code = await asyncio.gather(stdout_task, stderr_task, process.wait())
        if len(stdout) + len(stderr) > max_output_bytes:
            raise ToolOutputLimitExceeded("combined tool output exceeds the configured limit")
        return stdout, stderr, exit_code
    finally:
        if not stdout_task.done():
            stdout_task.cancel()
        if not stderr_task.done():
            stderr_task.cancel()
        await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)


async def _read_bounded(reader: asyncio.StreamReader, budget: _OutputBudget) -> bytes:
    chunks: list[bytes] = []
    while True:
        chunk = await reader.read(65_536)
        if not chunk:
            return b"".join(chunks)
        async with budget.lock:
            if len(chunk) > budget.remaining:
                raise ToolOutputLimitExceeded("tool output exceeds the configured limit")
            budget.remaining -= len(chunk)
        chunks.append(chunk)


async def _terminate(process: asyncio.subprocess.Process) -> None:
    if process.returncode is not None:
        return
    process.terminate()
    try:
        await asyncio.wait_for(process.wait(), timeout=5)
    except TimeoutError:
        process.kill()
        await process.wait()
