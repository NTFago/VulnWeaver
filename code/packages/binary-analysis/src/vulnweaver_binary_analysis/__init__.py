"""Inert x86/x64 ELF/PE inspection and bounded reverse-engineering adapters."""

from vulnweaver_binary_analysis.executor import (
    BinaryAnalysisExecutionError,
    BinaryImportExecutor,
)
from vulnweaver_binary_analysis.headers import (
    BinaryInspectionError,
    extract_strings,
    inspect_binary,
)
from vulnweaver_binary_analysis.tools import (
    AngrAdapter,
    BoundedCommandRunner,
    DetectItEasyAdapter,
    GhidraHeadlessAdapter,
    ObjdumpAdapter,
    ToolCancelled,
    ToolOutputLimitExceeded,
    ToolUnavailable,
    UpxAdapter,
    UpxUnpacker,
    parse_objdump_disassembly,
    parse_objdump_imports,
    parse_objdump_symbols,
)
from vulnweaver_binary_analysis.types import (
    BinaryAnalysisAggregate,
    BinaryAnalysisLimits,
    BinaryMetadata,
    ToolContribution,
    UpxOutcome,
)

__all__ = [
    "AngrAdapter",
    "BinaryAnalysisAggregate",
    "BinaryAnalysisExecutionError",
    "BinaryAnalysisLimits",
    "BinaryImportExecutor",
    "BinaryInspectionError",
    "BinaryMetadata",
    "BoundedCommandRunner",
    "DetectItEasyAdapter",
    "GhidraHeadlessAdapter",
    "ObjdumpAdapter",
    "ToolCancelled",
    "ToolContribution",
    "ToolOutputLimitExceeded",
    "ToolUnavailable",
    "UpxAdapter",
    "UpxUnpacker",
    "UpxOutcome",
    "extract_strings",
    "inspect_binary",
    "parse_objdump_disassembly",
    "parse_objdump_imports",
    "parse_objdump_symbols",
]
