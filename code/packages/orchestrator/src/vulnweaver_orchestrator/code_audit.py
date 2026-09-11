"""Agentic code audit: the model investigates, the tools only feed it.

The legacy audit handed the model one pre-truncated dump of indexed functions
and accepted whatever came back. This agent instead runs the shared
plan-execute-observe loop over the read-only investigation tools, so the model
chooses which function to open, follows call edges, searches for a pattern and
decides when it has enough to report. Scanner output enters the loop as leads to
confirm or refute, never as a conclusion.

Every candidate the agent reports is still anchored onto the immutable index by
the caller before it becomes a Finding, and still passes the independent review
and confirmation policy. The agent widens discovery; it does not widen trust.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from vulnweaver_artifact_store import ArtifactStore
from vulnweaver_contracts import (
    AgentRun,
    JsonObject,
    JsonValue,
    PermissionMode,
    StructuredFailure,
)
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
    AgentLoopStatus,
    AgentRunSink,
    ExecutedStep,
    PlannerGateway,
    StepOutcome,
)
from vulnweaver_orchestrator.audit_tools import (
    AUDIT_TOOLS,
    AuditStepExecutor,
    AuditWorkspace,
    AuditWorkspaceLimits,
    ReportedFinding,
    SymbolicRunner,
)

AUDIT_AGENT_OBJECTIVE = (
    "Audit this task's indexed code for location-anchored security defects. Work "
    "like an investigator: start from the leads and the function index, open the "
    "functions that matter, follow the call chain, and search for the sources and "
    "sinks involved. Reporting is the deliverable, not the searching: an "
    "investigation that reports nothing has failed this task. Report a candidate "
    "once the code you read substantiates it — you are the discovery stage, and "
    "an independent review plus a confirmation policy downstream exist precisely "
    "to filter false positives, so do not withhold a substantiated candidate out "
    "of doubt. Never report a location you did not read."
)

AUDIT_AGENT_INSTRUCTIONS = (
    "Use code-function-list, code-function-read, code-search, call-neighborhood, "
    "artifact-facts, static-leads and critical-logic to gather evidence before "
    "reporting. The static-leads entries are unverified scanner output: confirm or "
    "refute each one from code you read yourself, and do not report a lead you "
    "could not substantiate. Report source findings with path and start_line, and "
    "binary findings with the function address, copied exactly from what a tool "
    "returned; anything that does not resolve to an indexed function is discarded. "
    "Use symbolic-execute only for a binary function whose reachability or "
    "sink behaviour you cannot settle by reading: it runs inside the sandbox, may "
    "run at most twice per audit, and is refused unless the project enabled "
    "dynamic validation. Its result is an observation to reason about, never a "
    "finding on its own. Set verification_request to fuzz only when dynamic "
    "confirmation would settle a memory-safety question you cannot settle by "
    "reading. Arguments must never contain absolute paths or parent-directory "
    "segments. Report each candidate with finding-report as soon as the code you "
    "have read substantiates it rather than saving them for the end: an "
    "investigation that never reports is worth nothing. Return zero steps as soon "
    "as you have reported everything you can substantiate and explain why you are "
    "finished."
)

_MAX_INVESTIGATION_STEPS = 24
_MAX_INVESTIGATION_FIELD_CHARS = 400


@dataclass(frozen=True, slots=True)
class CodeAuditOutcome:
    """What one audit attempt produced, plus the trail of how it got there."""

    run: AgentRun
    findings: tuple[ReportedFinding, ...]
    steps: tuple[ExecutedStep, ...]
    degraded: bool
    fallback_code: str | None = None

    @property
    def investigation(self) -> list[JsonObject]:
        """Bounded, model-agnostic digest of the tool calls the agent made."""

        digest: list[JsonObject] = []
        for step in self.steps[:_MAX_INVESTIGATION_STEPS]:
            digest.append(
                {
                    "step_id": step.step_id,
                    "tool": f"{step.tool_name}@{step.tool_version}",
                    "succeeded": step.succeeded,
                    "failure_code": step.failure_code,
                    "observation": _bounded_observation(step.output),
                }
            )
        return digest


class _WorkspaceStepExecutor:
    """Adapt the workspace toolkit to the loop's step-executor protocol."""

    def __init__(self, inner: AuditStepExecutor) -> None:
        self._inner = inner

    async def execute(self, call: ScheduledToolCall) -> StepOutcome:
        output = await self._inner.execute(call)
        failure_code = output.get("reason_code") if output.get("failed") else None
        return StepOutcome(
            succeeded=not bool(output.get("failed")),
            output=output,
            failure_code=str(failure_code) if failure_code is not None else None,
        )


class AuditProgressSink(Protocol):
    async def add(self, run: AgentRun) -> None: ...


class CodeAuditAgent:
    """Run one bounded investigation over a task's immutable index."""

    def __init__(
        self,
        database: Database,
        gateway: PlannerGateway,
        store: ArtifactStore,
        *,
        sink: AgentRunSink | None = None,
        budget: AgentLoopBudget | None = None,
        limits: AuditWorkspaceLimits | None = None,
        symbolic_runner: SymbolicRunner | None = None,
        dynamic_verification_enabled: bool = False,
        clock: Callable[[], datetime] | None = None,
        monotonic: Callable[[], float] | None = None,
    ) -> None:
        self._database = database
        self._gateway = gateway
        self._store = store
        self._sink = sink
        self._symbolic_runner = symbolic_runner
        self._dynamic_verification_enabled = dynamic_verification_enabled
        # No planning-round cap: the investigation ends when the model reports
        # and stops asking for steps, or when the token budget runs out.
        self._budget = budget or AgentLoopBudget(
            max_plan_rejections=4,
            max_steps_per_plan=8,
            max_observation_chars=8_192,
        )
        self._limits = limits or AuditWorkspaceLimits()
        self._clock: Callable[[], datetime] = clock or (lambda: datetime.now(UTC))
        self._monotonic = monotonic

    async def audit(
        self,
        *,
        task_id: str,
        job_id: str,
        attempt: int,
        run_id: str,
        input_refs: tuple[str, ...] = (),
    ) -> CodeAuditOutcome:
        workspace = AuditWorkspace(self._database, self._store, task_id, limits=self._limits)
        await workspace.load()
        executor = AuditStepExecutor(
            workspace,
            symbolic_runner=self._symbolic_runner,
            dynamic_verification_enabled=(
                self._dynamic_verification_enabled or await self._project_opt_in(task_id)
            ),
        )
        registry = ToolRegistry(AUDIT_TOOLS)
        loop = AgentLoop(
            self._gateway,
            registry,
            PolicyEngine(registry),
            _WorkspaceStepExecutor(executor),
            sink=self._sink,
            tier=ModelTier.AUDIT,
            budget=self._budget,
            clock=self._clock,
            monotonic=self._monotonic,
        )
        request = AgentLoopRequest(
            task_id=task_id,
            run_id=run_id,
            objective=AUDIT_AGENT_OBJECTIVE,
            context=await self._context(task_id, workspace),
            policy_context=PolicyContext(
                artifact_kinds=workspace.artifact_kinds,
                permission_mode=PermissionMode.FULL_ACCESS,
            ),
            input_refs=input_refs or workspace.version_ids(),
            instructions=AUDIT_AGENT_INSTRUCTIONS,
        )
        result = await loop.run(request)
        fallback: StructuredFailure | None = result.fallback
        return CodeAuditOutcome(
            run=result.agent_run,
            findings=tuple(executor.reported),
            steps=result.steps,
            degraded=result.status is AgentLoopStatus.DEGRADED,
            fallback_code=str(fallback["code"]) if fallback is not None else None,
        )

    async def _project_opt_in(self, task_id: str) -> bool:
        """Dynamic validation is a project-level opt-in, resolved per task."""

        async with self._database.transaction() as repositories:
            task = await repositories.tasks.get(task_id)
            project = await repositories.projects.get(task["project_id"])
        return bool(project["exploit_validation_enabled"])

    async def _context(self, task_id: str, workspace: AuditWorkspace) -> JsonObject:
        """Everything the agent may rely on before it calls its first tool."""

        source_count = 0
        binary_count = 0
        for ref in workspace.function_refs():
            if ref.function["binary_location"] is not None:
                binary_count += 1
            else:
                source_count += 1
        context: JsonObject = {
            "task_id": task_id,
            "artifact_refs": list(workspace.version_ids()),
            "indexed_functions": {
                "total": workspace.function_count,
                "source": source_count,
                "binary": binary_count,
            },
            "static_leads": await workspace.static_leads(),
            "critical_logic": await workspace.critical_logic(),
            "binary_summary": await workspace.artifact_facts(kind="summary"),
        }
        return context


def _bounded_observation(output: JsonObject) -> JsonValue:
    encoded = json.dumps(output, ensure_ascii=False, sort_keys=True)
    if len(encoded) <= _MAX_INVESTIGATION_FIELD_CHARS:
        return output
    return {"truncated": True, "prefix": encoded[:_MAX_INVESTIGATION_FIELD_CHARS]}


def audit_run_id(job_id: str, attempt: int) -> str:
    """Stable per-attempt run id so a retry overwrites instead of duplicating."""

    digest = hashlib.sha256("\0".join((job_id, str(attempt))).encode()).hexdigest()[:32]
    return f"agent-run:semantic-audit:{digest}"


__all__ = [
    "AUDIT_AGENT_INSTRUCTIONS",
    "AUDIT_AGENT_OBJECTIVE",
    "AuditProgressSink",
    "CodeAuditAgent",
    "CodeAuditOutcome",
    "audit_run_id",
]
