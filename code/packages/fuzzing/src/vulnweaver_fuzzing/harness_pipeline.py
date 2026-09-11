"""Bounded harness generation -> compile -> repair pipeline.

Every attempt is bounded and observable: the model proposes source, the sandbox
compiles it, and structured compiler diagnostics feed at most ``max_repairs``
repair attempts. Exhausting the budget is a structured failure, never an
unbounded loop, and the control plane never compiles or executes anything
itself.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Protocol

from vulnweaver_contracts import JsonObject, ResourceBudget

from vulnweaver_fuzzing.harness_compiler import (
    HarnessCompileOutcome,
    HarnessCompiler,
)
from vulnweaver_fuzzing.harness_generator import HarnessGenerator
from vulnweaver_fuzzing.harness_loop import HarnessDiagnostic, HarnessLoopResult

MAX_REPAIRS = 2
_ABSOLUTE_MAX_REPAIRS = 8


class HarnessRepairer(Protocol):
    """Ask the planning model to repair source against compiler diagnostics."""

    async def repair(
        self, *, task_id: str, job_id: str, source: str, diagnostics: str
    ) -> str | None: ...


@dataclass(frozen=True, slots=True)
class HarnessPipelineResult:
    """Outcome of one bounded harness build."""

    status: str
    source: str
    diagnostics: tuple[HarnessDiagnostic, ...]
    compiled_ref: str | None = None
    loop: HarnessLoopResult | None = None

    @property
    def succeeded(self) -> bool:
        return self.status == "compiled" and self.compiled_ref is not None


class HarnessPipeline:
    """Drive one bounded harness build from prompt context to compiled artifact."""

    def __init__(
        self,
        compiler: HarnessCompiler,
        *,
        generator: HarnessGenerator | None = None,
        repairer: HarnessRepairer | None = None,
        max_repairs: int = MAX_REPAIRS,
    ) -> None:
        if max_repairs < 0 or max_repairs > _ABSOLUTE_MAX_REPAIRS:
            raise ValueError("harness repair budget must be between 0 and 8")
        self._compiler = compiler
        self._generator = generator
        self._repairer = repairer
        self._max_repairs = max_repairs

    async def build(
        self,
        *,
        task_id: str,
        job_id: str,
        artifact_version_id: str,
        context: JsonObject,
        budget: ResourceBudget,
        fixtures: tuple[str, ...] = (),
    ) -> HarnessPipelineResult:
        """Generate, compile and repair a harness within a fixed attempt budget."""
        if self._generator is None:
            return HarnessPipelineResult("unconfigured", "", ())
        source = await self._generator.generate(task_id=task_id, job_id=job_id, context=context)
        if source is None:
            return HarnessPipelineResult("generation_failed", "", ())

        diagnostics: list[HarnessDiagnostic] = []
        current = source
        for attempt in range(self._max_repairs + 1):
            outcome = await self._compile_attempt(
                current,
                attempt=attempt,
                job_id=job_id,
                artifact_version_id=artifact_version_id,
                budget=budget,
                fixtures=fixtures,
            )
            diagnostics.append(_diagnostic(outcome))
            if outcome.succeeded:
                loop = HarnessLoopResult("compiled", current, tuple(diagnostics))
                return HarnessPipelineResult(
                    "compiled", current, tuple(diagnostics), outcome.compiled_ref, loop
                )
            if attempt == self._max_repairs or self._repairer is None:
                break
            repaired = await self._repairer.repair(
                task_id=task_id,
                # Each repair round needs its own AgentRun id: the recorder
                # rejects a second append with identical content otherwise.
                job_id=f"{job_id}:repair:{attempt}",
                source=current,
                diagnostics="\n".join(outcome.diagnostics) or outcome.message,
            )
            if repaired is None or not repaired.strip() or repaired == current:
                break
            current = repaired
        loop = HarnessLoopResult("failed", current, tuple(diagnostics))
        return HarnessPipelineResult("failed", current, tuple(diagnostics), None, loop)

    async def _compile_attempt(
        self,
        source: str,
        *,
        attempt: int,
        job_id: str,
        artifact_version_id: str,
        budget: ResourceBudget,
        fixtures: tuple[str, ...],
    ) -> HarnessCompileOutcome:
        return await self._compiler.compile(
            source,
            request_id=f"harness-compile:{job_id}:{attempt}",
            artifact_version_id=artifact_version_id,
            fixtures=fixtures,
            budget=budget,
        )


def _diagnostic(outcome: HarnessCompileOutcome) -> HarnessDiagnostic:
    return HarnessDiagnostic(
        success=outcome.succeeded,
        message=outcome.message,
        output_ref=outcome.compiled_ref,
    )


def harness_artifact_name(source: str) -> str:
    """Deterministic, content-addressed harness source name for audit trails."""

    return "harness-" + hashlib.sha256(source.encode("utf-8")).hexdigest()[:16] + ".c"
