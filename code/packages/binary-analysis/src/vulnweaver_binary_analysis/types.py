"""Shared binary-analysis value objects and resource limits."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from vulnweaver_contracts import (
    BinaryArchitecture,
    BinaryBasicBlock,
    BinaryFormat,
    BinaryFunction,
    BinaryImport,
    BinaryInstruction,
    BinaryPseudocode,
    BinarySection,
    BinaryString,
    BinarySymbolicFact,
    BinaryToolRun,
    BinaryXref,
    JsonValue,
)


@dataclass(frozen=True, slots=True)
class BinaryAnalysisLimits:
    max_input_bytes: int = 512 * 1024 * 1024
    max_sections: int = 4096
    max_functions: int = 20_000
    max_instructions: int = 200_000
    max_basic_blocks: int = 100_000
    max_xrefs: int = 200_000
    max_pseudocode_functions: int = 20_000
    max_pseudocode_chars: int = 262_144
    max_symbolic_functions: int = 8
    max_symbolic_steps: int = 32
    max_symbolic_states: int = 32
    max_strings: int = 50_000
    max_string_chars: int = 4096
    min_string_chars: int = 4
    max_imports: int = 20_000
    max_tool_output_bytes: int = 8 * 1024 * 1024
    max_raw_output_chars: int = 1024 * 1024
    # Aligned with the sandbox request ceiling: one Ghidra/de4dot/facts pass
    # over a real-world binary legitimately needs more than the old 180-second
    # cap, and an 18 MB PE measured ~8 minutes warm — cold container starts
    # oversubscribe 600 seconds, so the operational stop now sits at 30 minutes.
    command_timeout_seconds: float = 1800.0

    def __post_init__(self) -> None:
        positive = {
            "max_input_bytes": self.max_input_bytes,
            "max_sections": self.max_sections,
            "max_functions": self.max_functions,
            "max_instructions": self.max_instructions,
            "max_basic_blocks": self.max_basic_blocks,
            "max_xrefs": self.max_xrefs,
            "max_pseudocode_functions": self.max_pseudocode_functions,
            "max_pseudocode_chars": self.max_pseudocode_chars,
            "max_symbolic_functions": self.max_symbolic_functions,
            "max_symbolic_steps": self.max_symbolic_steps,
            "max_symbolic_states": self.max_symbolic_states,
            "max_strings": self.max_strings,
            "max_string_chars": self.max_string_chars,
            "min_string_chars": self.min_string_chars,
            "max_imports": self.max_imports,
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
    dotnet: bool = False

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
    basic_blocks: tuple[BinaryBasicBlock, ...] = ()
    xrefs: tuple[BinaryXref, ...] = ()
    pseudocode: tuple[BinaryPseudocode, ...] = ()
    symbolic_facts: tuple[BinarySymbolicFact, ...] = ()
    imports: tuple[BinaryImport, ...] = ()
    compiler: str | None = None
    packer: str | None = None
    packed: bool | None = None


@dataclass(frozen=True, slots=True)
class UpxOutcome:
    run: BinaryToolRun
    packed: bool
    unpacked_path: Path | None = None


@dataclass(frozen=True, slots=True)
class CollectionCoverage:
    """Truncation accounting for one aggregate collection.

    ``offered`` counts every item any tool presented for the collection across
    all contributions; ``retained`` is what the aggregate actually holds.  Only
    novel items rejected because the configured limit was reached count as
    truncation — deduplication is normal merging, not data loss — and ``reason``
    names the limit plus how many unique items it dropped.
    """

    collection: str
    offered: int
    retained: int
    limit: int
    dropped_for_limit: int = 0

    @property
    def truncated(self) -> bool:
        return self.dropped_for_limit > 0

    @property
    def reason(self) -> str | None:
        if self.dropped_for_limit == 0:
            return None
        return (
            f"{self.dropped_for_limit} unique items dropped: "
            f"{self.collection} limit {self.limit} reached"
        )

    def document(self) -> dict[str, JsonValue]:
        return {
            "offered": self.offered,
            "retained": self.retained,
            "limit": self.limit,
            "truncated": self.truncated,
            "reason": self.reason,
        }


_COVERAGE_COLLECTIONS = (
    "functions",
    "instructions",
    "basic_blocks",
    "xrefs",
    "pseudocode",
    "symbolic_facts",
    "imports",
)


class _CoverageTracker:
    """Mutable per-collection accounting behind the aggregate's coverage view."""

    def __init__(self) -> None:
        self._offered = {name: 0 for name in _COVERAGE_COLLECTIONS}
        self._dropped_for_limit = {name: 0 for name in _COVERAGE_COLLECTIONS}
        self._limits: dict[str, int] = {}

    def set_limit(self, collection: str, limit: int) -> None:
        self._limits[collection] = limit

    def record_offered(self, collection: str, count: int) -> None:
        self._offered[collection] += count

    def record_dropped_for_limit(self, collection: str, count: int) -> None:
        self._dropped_for_limit[collection] += count

    def snapshot(self, retained: Mapping[str, int]) -> dict[str, CollectionCoverage]:
        view: dict[str, CollectionCoverage] = {}
        for name in _COVERAGE_COLLECTIONS:
            view[name] = CollectionCoverage(
                collection=name,
                offered=self._offered[name],
                retained=retained.get(name, 0),
                limit=self._limits.get(name, 0),
                dropped_for_limit=self._dropped_for_limit[name],
            )
        return view


@dataclass(slots=True)
class BinaryAnalysisAggregate:
    metadata: BinaryMetadata
    functions: list[BinaryFunction] = field(default_factory=lambda: _empty_functions())
    instructions: list[BinaryInstruction] = field(default_factory=lambda: _empty_instructions())
    basic_blocks: list[BinaryBasicBlock] = field(default_factory=lambda: _empty_basic_blocks())
    xrefs: list[BinaryXref] = field(default_factory=lambda: _empty_xrefs())
    pseudocode: list[BinaryPseudocode] = field(default_factory=lambda: _empty_pseudocode())
    symbolic_facts: list[BinarySymbolicFact] = field(
        default_factory=lambda: _empty_symbolic_facts()
    )
    strings: list[BinaryString] = field(default_factory=lambda: _empty_strings())
    imports: list[BinaryImport] = field(default_factory=lambda: _empty_imports())
    tool_runs: list[BinaryToolRun] = field(default_factory=lambda: _empty_tool_runs())
    compiler: str | None = None
    packer: str | None = None
    packed: bool = False
    strings_offered: int = 0
    strings_truncated: bool = False
    _coverage: _CoverageTracker = field(default_factory=_CoverageTracker, repr=False, compare=False)

    def __post_init__(self) -> None:
        self.compiler = self.metadata.compiler
        self.packer = self.metadata.packer
        self.packed = self.metadata.packed
        self._coverage.set_limit("functions", 0)
        self._coverage.set_limit("instructions", 0)
        self._coverage.set_limit("basic_blocks", 0)
        self._coverage.set_limit("xrefs", 0)
        self._coverage.set_limit("pseudocode", 0)
        self._coverage.set_limit("symbolic_facts", 0)
        self._coverage.set_limit("imports", 0)

    def record_limits(self, limits: BinaryAnalysisLimits) -> None:
        """Declare the limits that later merges are accounted against."""
        self._coverage.set_limit("functions", limits.max_functions)
        self._coverage.set_limit("instructions", limits.max_instructions)
        self._coverage.set_limit("basic_blocks", limits.max_basic_blocks)
        self._coverage.set_limit("xrefs", limits.max_xrefs)
        self._coverage.set_limit("pseudocode", limits.max_pseudocode_functions)
        self._coverage.set_limit("symbolic_facts", limits.max_symbolic_functions)
        self._coverage.set_limit("imports", limits.max_imports)

    def record_string_extraction(self, *, offered: int, retained: int, limit: int) -> None:
        """Account for the string extractor's own silent cap (CR-08)."""
        self.strings_offered = offered
        self.strings_truncated = offered > retained and retained >= limit

    def coverage(self) -> dict[str, JsonValue]:
        """JSON-safe per-collection truncation accounting for reports and agents."""
        retained = {
            "functions": len(self.functions),
            "instructions": len(self.instructions),
            "basic_blocks": len(self.basic_blocks),
            "xrefs": len(self.xrefs),
            "pseudocode": len(self.pseudocode),
            "symbolic_facts": len(self.symbolic_facts),
            "imports": len(self.imports),
        }
        document: dict[str, JsonValue] = {
            name: stats.document()
            for name, stats in self._coverage.snapshot(retained).items()
        }
        document["strings"] = {
            "offered": self.strings_offered,
            "retained": len(self.strings),
            "limit": 0,
            "truncated": self.strings_truncated,
            "reason": (
                f"{max(0, self.strings_offered - len(self.strings))} strings dropped: "
                "max_strings limit reached"
                if self.strings_truncated
                else None
            ),
        }
        document["complete"] = not any(
            isinstance(value, dict) and bool(value.get("truncated"))
            for value in document.values()
        )
        return document

    def merge(self, contribution: ToolContribution, limits: BinaryAnalysisLimits) -> None:
        self.record_limits(limits)
        self.tool_runs.append(contribution.run)
        self._coverage.record_offered("functions", len(contribution.functions))
        function_keys = {(item["address"], item["name"]) for item in self.functions}
        for item in contribution.functions:
            key = (item["address"], item["name"])
            if key in function_keys:
                continue
            if len(self.functions) >= limits.max_functions:
                self._coverage.record_dropped_for_limit("functions", 1)
                continue
            self.functions.append(item)
            function_keys.add(key)

        self._coverage.record_offered("instructions", len(contribution.instructions))
        instruction_addresses = {item["address"] for item in self.instructions}
        for item in contribution.instructions:
            if item["address"] in instruction_addresses:
                continue
            if len(self.instructions) >= limits.max_instructions:
                self._coverage.record_dropped_for_limit("instructions", 1)
                continue
            self.instructions.append(item)
            instruction_addresses.add(item["address"])

        self._coverage.record_offered("basic_blocks", len(contribution.basic_blocks))
        block_keys = {
            (item["start_address"], item["end_address"], item["function_name"])
            for item in self.basic_blocks
        }
        for item in contribution.basic_blocks:
            key = (item["start_address"], item["end_address"], item["function_name"])
            if key in block_keys:
                continue
            if len(self.basic_blocks) >= limits.max_basic_blocks:
                self._coverage.record_dropped_for_limit("basic_blocks", 1)
                continue
            self.basic_blocks.append(item)
            block_keys.add(key)

        self._coverage.record_offered("xrefs", len(contribution.xrefs))
        xref_keys = {
            (item["source_address"], item["target_address"], item["type"]) for item in self.xrefs
        }
        for item in contribution.xrefs:
            key = (item["source_address"], item["target_address"], item["type"])
            if key in xref_keys:
                continue
            if len(self.xrefs) >= limits.max_xrefs:
                self._coverage.record_dropped_for_limit("xrefs", 1)
                continue
            self.xrefs.append(item)
            xref_keys.add(key)

        self._coverage.record_offered("pseudocode", len(contribution.pseudocode))
        pseudocode_keys = {(item["address"], item["tool_name"]) for item in self.pseudocode}
        for item in contribution.pseudocode:
            key = (item["address"], item["tool_name"])
            if key in pseudocode_keys:
                continue
            if len(self.pseudocode) >= limits.max_pseudocode_functions:
                self._coverage.record_dropped_for_limit("pseudocode", 1)
                continue
            self.pseudocode.append(item)
            pseudocode_keys.add(key)

        self._coverage.record_offered("symbolic_facts", len(contribution.symbolic_facts))
        symbolic_addresses = {item["function_address"] for item in self.symbolic_facts}
        for item in contribution.symbolic_facts:
            if item["function_address"] in symbolic_addresses:
                continue
            if len(self.symbolic_facts) >= limits.max_symbolic_functions:
                self._coverage.record_dropped_for_limit("symbolic_facts", 1)
                continue
            self.symbolic_facts.append(item)
            symbolic_addresses.add(item["function_address"])

        self._coverage.record_offered("imports", len(contribution.imports))
        import_keys = {
            (item["library"], item["name"], item["ordinal"], item["address"])
            for item in self.imports
        }
        for item in contribution.imports:
            key = (item["library"], item["name"], item["ordinal"], item["address"])
            if key in import_keys:
                continue
            if len(self.imports) >= limits.max_imports:
                self._coverage.record_dropped_for_limit("imports", 1)
                continue
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


def _empty_basic_blocks() -> list[BinaryBasicBlock]:
    return []


def _empty_xrefs() -> list[BinaryXref]:
    return []


def _empty_pseudocode() -> list[BinaryPseudocode]:
    return []


def _empty_symbolic_facts() -> list[BinarySymbolicFact]:
    return []


def _empty_strings() -> list[BinaryString]:
    return []


def _empty_imports() -> list[BinaryImport]:
    return []


def _empty_tool_runs() -> list[BinaryToolRun]:
    return []
