"""Bounded fuzzing budgets and deterministic crash triage."""

from vulnweaver_fuzzing.executor import FuzzExecutionService, build_fuzz_input_bundle
from vulnweaver_fuzzing.harness_generator import HarnessGenerator, HarnessModel
from vulnweaver_fuzzing.harness_loop import (
    HarnessDiagnostic,
    HarnessLoopResult,
    compile_repair_loop,
)
from vulnweaver_fuzzing.job_executor import FuzzJobExecutor
from vulnweaver_fuzzing.profiles import (
    AFL_CASR_OUTPUT_NAMES,
    AFL_CASR_PROFILE,
    AFL_CASR_TOOL_NAME,
    AFL_CASR_TOOL_VERSION,
    CASR_TOOL_NAME,
    CASR_TOOL_VERSION,
    afl_casr_command_profile,
    afl_casr_tool_spec,
)
from vulnweaver_fuzzing.triage import (
    CrashTriageError,
    CrashTriageService,
    FuzzBudgetGate,
    FuzzBudgetLimits,
    validate_fuzz_request,
)

__all__ = [
    "CrashTriageError",
    "CrashTriageService",
    "FuzzExecutionService",
    "FuzzJobExecutor",
    "FuzzBudgetGate",
    "FuzzBudgetLimits",
    "AFL_CASR_OUTPUT_NAMES",
    "AFL_CASR_PROFILE",
    "AFL_CASR_TOOL_NAME",
    "AFL_CASR_TOOL_VERSION",
    "CASR_TOOL_NAME",
    "CASR_TOOL_VERSION",
    "afl_casr_command_profile",
    "afl_casr_tool_spec",
    "build_fuzz_input_bundle",
    "validate_fuzz_request",
    "HarnessDiagnostic",
    "HarnessLoopResult",
    "compile_repair_loop",
    "HarnessGenerator",
    "HarnessModel",
]
