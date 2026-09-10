"""Bounded harness compile/diagnose/repair orchestration primitives."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class HarnessDiagnostic:
    success: bool
    message: str
    output_ref: str | None = None


@dataclass(frozen=True, slots=True)
class HarnessLoopResult:
    status: str
    source: str
    diagnostics: tuple[HarnessDiagnostic, ...]


def compile_repair_loop(
    source: str,
    compile_once: Callable[[str], HarnessDiagnostic],
    repair_once: Callable[[str, HarnessDiagnostic], str],
    *,
    max_repairs: int = 2,
) -> HarnessLoopResult:
    """Run a bounded compiler feedback loop.

    ``compile_once`` is an injected, policy-bound operation. This module never
    accepts or executes command strings, making the orchestration safe to use
    from the control plane while the actual compiler remains in the sandbox.
    """
    if not source.strip() or max_repairs < 0 or max_repairs > 8:
        raise ValueError("invalid harness source or repair budget")
    current = source
    diagnostics: list[HarnessDiagnostic] = []
    for attempt in range(max_repairs + 1):
        diagnostic = compile_once(current)
        diagnostics.append(diagnostic)
        if diagnostic.success:
            return HarnessLoopResult("compiled", current, tuple(diagnostics))
        if attempt == max_repairs:
            break
        repaired = repair_once(current, diagnostic)
        if not repaired.strip() or repaired == current:
            break
        current = repaired
    return HarnessLoopResult("failed", current, tuple(diagnostics))
