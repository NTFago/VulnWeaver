"""Shared binary-analysis value objects and resource limits."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from vulnweaver_contracts import (
    BinaryArchitecture,
    BinaryFormat,
    BinaryFunction,
    BinaryImport,
    BinaryInstruction,
    BinarySection,
    BinaryString,
    BinaryToolRun,
)


@dataclass(frozen=True, slots=True)
class BinaryAnalysisLimits:
    max_input_bytes: int = 512 * 1024 * 1024
    max_sections: int = 4096
    max_functions: int = 20_000
    max_instructions: int = 200_000
    max_strings: int = 50_000
    max_string_chars: int = 4096
    min_string_chars: int = 4
    max_tool_output_bytes: int = 8 * 1024 * 1024
    max_raw_output_chars: int = 1024 * 1024
    command_timeout_seconds: float = 180.0

    def __post_init__(self) -> None:
        positive = {
            "max_input_bytes": self.max_input_bytes,
            "max_sections": self.max_sections,
            "max_functions": self.max_functions,
            "max_instructions": self.max_instructions,
            "max_strings": self.max_strings,
            "max_string_chars": self.max_string_chars,
            "min_string_chars": self.min_string_chars,
            "max_tool_output_bytes": self.max_tool_output_bytes,
            "max_raw_output_chars": self.max_raw_output_chars,
        }
        if any(value < 1 for value in positive.values()):
            raise ValueError("binary analysis limits must be positive")
        if self.command_timeout_seconds <= 0:
            raise ValueError("command timeout must be positive")
        if self.min_string_chars > self.max_string_chars:
            raise ValueError("minimum string length cannot exceed maximum string length")


@dataclass(frozen=True, slots=True)
class BinaryMetadata:
    format: BinaryFormat
    architecture: BinaryArchitecture
    bits: Literal[32, 64]
    endianness: Literal["little", "big"]
    image_base: int
    entry_point: int
    sections: tuple[BinarySection, ...]
    packed: bool = False
    packer: str | None = None
    compiler: str | None = None

    def offset_to_virtual_address(self, offset: int) -> int | None:
        for section in self.sections:
            start = section["file_offset"]
            end = start + section["file_size"]
            if start <= offset < end:
                return section["virtual_address"] + (offset - start)
        return None

    def virtual_address_to_offset(self, address: int) -> int | None:
        for section in self.sections:
            start = section["virtual_address"]
            span = max(section["virtual_size"], section["file_size"])
            if start <= address < start + span:
                delta = address - start
                if delta < section["file_size"]:
                    return section["file_offset"] + delta
        return None


@dataclass(frozen=True, slots=True)
class ToolContribution:
    run: BinaryToolRun
    functions: tuple[BinaryFunction, ...] = ()
    instructions: tuple[BinaryInstruction, ...] = ()
    imports: tuple[BinaryImport, ...] = ()
    compiler: str | None = None
    packer: str | None = None
    packed: bool | None = None


@dataclass(frozen=True, slots=True)
class UpxOutcome:
    run: BinaryToolRun
    packed: bool
    unpacked_path: Path | None = None


@dataclass(slots=True)
class BinaryAnalysisAggregate:
    metadata: BinaryMetadata
    functions: list[BinaryFunction] = field(default_factory=lambda: _empty_functions())
    instructions: list[BinaryInstruction] = field(default_factory=lambda: _empty_instructions())
    strings: list[BinaryString] = field(default_factory=lambda: _empty_strings())
    imports: list[BinaryImport] = field(default_factory=lambda: _empty_imports())
    tool_runs: list[BinaryToolRun] = field(default_factory=lambda: _empty_tool_runs())
    compiler: str | None = None
    packer: str | None = None
    packed: bool = False

    def __post_init__(self) -> None:
        self.compiler = self.metadata.compiler
        self.packer = self.metadata.packer
        self.packed = self.metadata.packed

    def merge(self, contribution: ToolContribution, limits: BinaryAnalysisLimits) -> None:
        self.tool_runs.append(contribution.run)
        function_keys = {(item["address"], item["name"]) for item in self.functions}
        for item in contribution.functions:
            key = (item["address"], item["name"])
            if key not in function_keys and len(self.functions) < limits.max_functions:
                self.functions.append(item)
                function_keys.add(key)

        instruction_addresses = {item["address"] for item in self.instructions}
        for item in contribution.instructions:
            if (
                item["address"] not in instruction_addresses
                and len(self.instructions) < limits.max_instructions
            ):
                self.instructions.append(item)
                instruction_addresses.add(item["address"])

        import_keys = {
            (item["library"], item["name"], item["ordinal"], item["address"])
            for item in self.imports
        }
        for item in contribution.imports:
            key = (item["library"], item["name"], item["ordinal"], item["address"])
            if key not in import_keys and len(self.imports) < limits.max_functions:
                self.imports.append(item)
                import_keys.add(key)

        if contribution.compiler:
            self.compiler = contribution.compiler
        if contribution.packer:
            self.packer = contribution.packer
        if contribution.packed is not None:
            self.packed = contribution.packed


def _empty_functions() -> list[BinaryFunction]:
    return []


def _empty_instructions() -> list[BinaryInstruction]:
    return []


def _empty_strings() -> list[BinaryString]:
    return []


def _empty_imports() -> list[BinaryImport]:
    return []


def _empty_tool_runs() -> list[BinaryToolRun]:
    return []
