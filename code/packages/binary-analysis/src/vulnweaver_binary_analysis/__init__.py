"""Inert x86/x64 ELF/PE inspection and bounded reverse-engineering adapters."""

from vulnweaver_binary_analysis.critical_logic import (
    CriticalLogicCandidate,
    discover_critical_logic,
)
from vulnweaver_binary_analysis.deobfuscation import (
    recover_readable_pseudocode,
    validate_model_readable_pseudocode,
)
from vulnweaver_binary_analysis.executor import (
    BinaryAnalysisExecutionError,
    BinaryImportExecutor,
    BinaryPlanningHook,
    CriticalLogicHook,
    ReadablePseudocodeHook,
)
from vulnweaver_binary_analysis.headers import (
    BinaryInspectionError,
    extract_strings,
    inspect_binary,
)
from vulnweaver_binary_analysis.obfuscation import (
    ObfuscationAssessment,
    assess_control_flow_flattening,
)
from vulnweaver_binary_analysis.profiles import (
    binary_command_profile,
    binary_tool_spec,
    binary_unpack_command_profile,
    binary_unpack_tool_spec,
)
from vulnweaver_binary_analysis.tools import (
    AngrAdapter,
    BinaryFactsAdapter,
    BinaryFactsSandbox,
    BoundedCommandRunner,
    DetectItEasyAdapter,
    GhidraHeadlessAdapter,
    ObjdumpAdapter,
    ToolCancelled,
    ToolUnavailable,
    UpxAdapter,
    UpxUnpacker,
    derive_objdump_control_flow,
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
from vulnweaver_binary_analysis.unpacking import (
    BinaryUnpackSandboxAdapter,
    De4dotUnpacker,
    LiefRebuilder,
    UnipackerUnpacker,
    UnpackAttempt,
    UnpackChainOutcome,
    Unpacker,
    UnpackerChain,
    UpxCliUnpacker,
    XorRegionUnpacker,
)

__all__ = [
    "AngrAdapter",
    "binary_command_profile",
    "binary_tool_spec",
    "binary_unpack_command_profile",
    "binary_unpack_tool_spec",
    "BinaryAnalysisAggregate",
    "BinaryAnalysisExecutionError",
    "BinaryAnalysisLimits",
    "BinaryImportExecutor",
    "BinaryPlanningHook",
    "CriticalLogicHook",
    "ReadablePseudocodeHook",
    "BinaryInspectionError",
    "BinaryMetadata",
    "BinaryUnpackSandboxAdapter",
    "De4dotUnpacker",
    "LiefRebuilder",
    "ObfuscationAssessment",
    "CriticalLogicCandidate",
    "BoundedCommandRunner",
    "BinaryFactsAdapter",
    "BinaryFactsSandbox",
    "DetectItEasyAdapter",
    "GhidraHeadlessAdapter",
    "ObjdumpAdapter",
    "ToolCancelled",
    "ToolContribution",
    "ToolUnavailable",
    "UnpackAttempt",
    "UnpackChainOutcome",
    "Unpacker",
    "UnpackerChain",
    "UnipackerUnpacker",
    "UpxAdapter",
    "UpxCliUnpacker",
    "UpxUnpacker",
    "UpxOutcome",
    "XorRegionUnpacker",
    "derive_objdump_control_flow",
    "extract_strings",
    "inspect_binary",
    "parse_objdump_disassembly",
    "parse_objdump_imports",
    "parse_objdump_symbols",
    "assess_control_flow_flattening",
    "discover_critical_logic",
    "recover_readable_pseudocode",
    "validate_model_readable_pseudocode",
]
