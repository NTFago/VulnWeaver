"""Reverse-analysis planning agent: model-selected symbolic execution targets.

The agent wraps the bounded plan-execute-observe loop around one registered
``angr-targeted-analysis`` tool. The binary executor supplies immutable facts
(packer, obfuscation assessments, function table) and an ``run_angr`` runner
backed by the real AngrAdapter; the model selects which addresses deserve
targeted symbolic execution, the loop executes those steps through the runner,
and every decision lands on one aggregated ``AgentRun``. Without a configured
model the loop degrades and the caller keeps its fixed pipeline.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol, cast

from vulnweaver_contracts import AgentRun, ArtifactKind, JsonObject, PermissionMode, ResourceBudget
from vulnweaver_model_gateway import ModelTier
from vulnweaver_persistence import Database
from vulnweaver_tool_runtime import (
    PolicyContext,
    PolicyEngine,
    ScheduledToolCall,
    ToolRegistry,
)

from vulnweaver_orchestrator.agent_loop import (
    AgentLoop,
    AgentLoopBudget,
    AgentLoopRequest,
    AgentLoopResult,
    AgentRunSink,
    PlannerGateway,
    StepOutcome,
)

_MAX_PLANNED_TARGETS = 16
_ANGR_TOOL: dict[str, object] = {
    "schema_version": "1.0.0",
    "name": "angr-targeted-analysis",
    "version": "1.0.0",
    "image_digest": "sha256:" + "0" * 64,
    "risk_level": "medium",
    "accepted_artifacts": ["elf", "pe", "derived"],
    "command_schema": {
        "type": "object",
        "additionalProperties": False,
        "required": ["addresses"],
        "properties": {
            "addresses": {
                "type": "array",
                "minItems": 1,
                "maxItems": _MAX_PLANNED_TARGETS,
                "items": {"type": "integer", "minimum": 0},
            },
            "reason": {"type": "string", "minLength": 1, "maxLength": 1024},
        },
    },
    "output_schema": {"type": "object"},
    "network_policy": {"access": "none", "allowed_hosts": []},
    "filesystem_policy": {
        "input_read_only": True,
        "isolated_output": True,
        "allow_host_paths": False,
    },
    "resource_limits": {
        "max_model_tokens": 1_000_000,
        "cpu_millis": 4_000_000,
        "memory_bytes": 8 * 1024 * 1024 * 1024,
        "disk_bytes": 8 * 1024 * 1024 * 1024,
        "max_tool_concurrency": 1,
        "max_dynamic_runs": 4,
        "timeout_seconds": 3600,
    },
    "approval_required": False,
    "timeout_seconds": 1800,
    "retry_policy": {
        "max_attempts": 1,
        "backoff_seconds": 0,
        "retryable_failure_kinds": [],
    },
}


class AngrRunner(Protocol):
    """Worker-backed execution of one targeted angr analysis."""

    async def __call__(self, target_addresses: tuple[int, ...]) -> JsonObject: ...


@dataclass(frozen=True, slots=True)
class PlannedTargets:
    targets: tuple[int, ...]
    agent_run: AgentRun
    degraded: bool
    fallback_code: str | None


class _AngrStepExecutor:
    """Runs planned angr steps through the worker runner and observes results."""

    def __init__(self, runner: AngrRunner) -> None:
        self._runner = runner
        self.executed: list[tuple[str, tuple[int, ...]]] = []

    async def execute(self, call: ScheduledToolCall) -> StepOutcome:
        raw = call.arguments.get("addresses")
        addresses = cast(list[object], raw) if isinstance(raw, list) else []
        targets = tuple(sorted({int(value) for value in addresses if isinstance(value, int)}))
        if not targets:
            return StepOutcome(False, {}, failure_code="planning.no_valid_addresses")
        observation = await self._runner(targets)
        self.executed.append((call.step_id, targets))
        return StepOutcome(True, observation, artifact_refs=())


class ReversePlanningAgent:
    """Bounded planning loop for one binary reverse-analysis Job."""

    def __init__(
        self,
        gateway: PlannerGateway,
        database: Database,
        *,
        sink: AgentRunSink | None = None,
        budget: AgentLoopBudget | None = None,
        clock: Callable[[], datetime] | None = None,
        monotonic: Callable[[], float] | None = None,
    ) -> None:
        self._gateway = gateway
        self._database = database
        self._sink = sink
        self._budget = budget or AgentLoopBudget(
            max_planning_rounds=2, max_plan_rejections=1
        )
        self._clock: Callable[[], datetime] = clock or (lambda: datetime.now(UTC))
        self._monotonic: Callable[[], float] | None = monotonic

    async def plan(
        self,
        *,
        task_id: str,
        job_id: str,
        facts: JsonObject,
        run_angr: AngrRunner,
    ) -> PlannedTargets:
        run_id = f"agent-run:reverse-plan:{job_id}"
        input_version = str(facts.get("input_artifact_version_id", "artifact-version:unknown"))
        request = AgentLoopRequest(
            task_id=task_id,
            run_id=run_id,
            objective=(
                "Plan targeted symbolic execution for one binary reverse-analysis "
                "job: pick the function addresses whose analysis benefits most from "
                "angr (dispatcher-like, flattened or security-relevant functions)."
            ),
            context=facts,
            policy_context=PolicyContext(
                artifact_kinds={input_version: ArtifactKind.ELF},
                resource_budget=cast(ResourceBudget, _budget()),
                permission_mode=PermissionMode.FULL_ACCESS,
            ),
            input_refs=(input_version,),
        )
        executor = _AngrStepExecutor(run_angr)
        loop = AgentLoop(
            self._gateway,
            ToolRegistry([_ANGR_TOOL]),
            PolicyEngine(ToolRegistry([_ANGR_TOOL])),
            executor,
            sink=self._sink,
            tier=ModelTier.PLANNING,
            budget=self._budget,
            clock=self._clock,
            monotonic=self._monotonic,
        )
        result: AgentLoopResult = await loop.run(request)
        targets = tuple(
            sorted({address for _, targets in executor.executed for address in targets})
        )[:_MAX_PLANNED_TARGETS]
        fallback_code = result.fallback["code"] if result.fallback is not None else None
        return PlannedTargets(
            targets=targets,
            agent_run=result.agent_run,
            degraded=result.degraded,
            fallback_code=fallback_code,
        )


class DatabaseAgentRunSink:
    """Persist aggregated loop runs into the agent_runs table."""

    def __init__(self, database: Database) -> None:
        self._database = database

    async def add(self, run: AgentRun) -> None:
        async with self._database.transaction() as repositories:
            await repositories.agent_runs.add(run)


def _budget() -> dict[str, int]:
    return {
        "max_model_tokens": 1_000_000,
        "cpu_millis": 4_000_000,
        "memory_bytes": 8 * 1024 * 1024 * 1024,
        "disk_bytes": 8 * 1024 * 1024 * 1024,
        "max_tool_concurrency": 1,
        "max_dynamic_runs": 4,
        "timeout_seconds": 3600,
    }


def planning_context(
    *,
    input_artifact_version_id: str,
    packed: bool,
    packer: str | None,
    functions: list[dict[str, object]],
    obfuscation: list[dict[str, object]],
    basic_block_count: int,
    xref_count: int,
    pseudocode_count: int,
) -> JsonObject:
    """Build the bounded, service-owned facts the planner may rely on."""
    return cast(
        JsonObject,
        {
            "input_artifact_version_id": input_artifact_version_id,
            "packed": packed,
            "packer": packer,
            "function_count": len(functions),
            "functions": functions[:64],
            "obfuscation": obfuscation[:16],
            "basic_block_count": basic_block_count,
            "xref_count": xref_count,
            "pseudocode_count": pseudocode_count,
        },
    )

