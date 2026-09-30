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
import logging
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol, cast

from vulnweaver_artifact_store import ArtifactStore
from vulnweaver_contracts import (
    AgentRun,
    DecisionRecord,
    JsonObject,
    JsonValue,
    PermissionMode,
    RunStatus,
    StructuredFailure,
    TokenUsage,
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
    LoopProgress,
    LoopResume,
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
from vulnweaver_orchestrator.checkpoints import CheckpointStore
from vulnweaver_orchestrator.investigation_memory import memory_context_entry

LOGGER = logging.getLogger("vulnweaver.code_audit")

# Durable resume state for the audit investigation.  The node is task-scoped;
# the state itself names the job so a retry attempt of the same job resumes,
# while a rerun of the task (new job) starts fresh.
AUDIT_CHECKPOINT_NODE = "semantic-audit-agent"
_MAX_CHECKPOINT_STEPS = 256
_MAX_CHECKPOINT_FINDINGS = 64

AUDIT_AGENT_OBJECTIVE = (
    "Audit this task's indexed code for location-anchored security defects. Work "
    "like an investigator: start from the leads and the function index, open the "
    "functions that matter, follow the call chain, and search for the sources and "
    "sinks involved. Reporting is the deliverable, not the searching: an "
    "investigation that reports nothing has failed this task. Report a candidate "
    "once the code you read substantiates it — you are the discovery stage, and "
    "an independent review plus a confirmation policy downstream exist precisely "
    "to filter false positives, so do not withhold a substantiated candidate out "
    "of doubt. Never report a location you did not read. Once you have reported "
    "every candidate the code supports and have no specific unresolved lead left "
    "to name, stop: return zero steps rather than opening another line of "
    "enquiry. More browsing will not add findings."
)

AUDIT_AGENT_INSTRUCTIONS = (
    "Evidence before conclusions. Orient with code-function-list, artifact-facts, "
    "static-leads and critical-logic; open what matters with code-function-read; "
    "follow edges with call-neighborhood; locate patterns with code-search. "
    "static-leads is unverified scanner output: confirm or refute each lead from "
    "code you read yourself, never from the lead text alone.\n\n"
    "Tool contracts. Every step must copy input_refs verbatim from "
    "context.artifact_refs — an invented reference makes the Policy Engine reject "
    "the whole plan and wastes a round. Keep step_id unique inside one plan, and "
    "never put absolute paths or parent-directory segments in arguments. Use "
    "symbolic-execute only for a binary function whose reachability or sink "
    "behaviour you cannot settle by reading: it runs in the sandbox, at most "
    "twice per audit, only when the project enabled dynamic validation, and its "
    "result is an observation to reason about — never a finding on its own.\n\n"
    "Reporting discipline. Report a candidate with finding-report as soon as the "
    "code you have read substantiates it; findings saved for the end are findings "
    "lost to a deadline. Choose the most specific applicable CWE, and make the "
    "rationale name its evidence: the function you read, the line or address, and "
    "how attacker-controlled data reaches the sink. Source findings need path and "
    "start_line; binary findings need the function address copied exactly from a "
    "tool result — anything that does not anchor to an indexed function is "
    "discarded. Set verification_request to fuzz only when dynamic confirmation "
    "would settle a memory-safety question that reading cannot: the request "
    "launches a bounded sandbox fuzzing campaign against the anchored artifact "
    "immediately — at most a few per audit — so spend it where a crash would "
    "genuinely decide the candidate.\n\n"
    "Investigation memory. context.prior_investigations holds the conclusions of "
    "earlier audits of this same project: findings that were already anchored and "
    "recorded, candidates whose locations failed anchoring (never re-report those "
    "locations unless you have new evidence), and how far each dig actually got. "
    "Build on this instead of repeating it -- spend your rounds on leads the "
    "memory shows unexplored.\n\n"
    "Resuming. If the context already shows investigation history, this audit was "
    "interrupted and is continuing: treat those steps as already executed, do not "
    "repeat them, and continue from the last observation.\n\n"
    "Stop when done. Once every substantiated candidate is reported and you can "
    "name no specific unresolved lead, return zero steps and explain why you are "
    "finished. More browsing will not add findings."
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
    # False when the loop stopped without the model declaring itself finished
    # (deadline, or the model degrading). The caller must not read such a run as
    # "the audit looked and found nothing".
    completed: bool = True
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
        checkpoint_store: CheckpointStore | None = None,
        clock: Callable[[], datetime] | None = None,
        monotonic: Callable[[], float] | None = None,
    ) -> None:
        self._database = database
        self._gateway = gateway
        self._store = store
        self._sink = sink
        self._symbolic_runner = symbolic_runner
        self._dynamic_verification_enabled = dynamic_verification_enabled
        self._checkpoints = checkpoint_store
        # No planning-round cap: the investigation ends when the model reports
        # and stops asking for steps, or when the model degrades.  With the token
        # budget gone that left nothing bounding a run that keeps planning
        # successfully, so a wall-clock deadline is the backstop.
        self._budget = budget or AgentLoopBudget(
            max_plan_rejections=4,
            max_steps_per_plan=8,
            max_observation_chars=8_192,
            soft_round_limit=6,
            # Wall clock is the loop's only hard backstop (ADR-027).  The
            # course-era calibrations (30 minutes, then two hours) starved
            # real-world samples; eight hours is the long-horizon default and
            # deployments can still override it via AGENT_AUDIT_DEADLINE_SECONDS.
            deadline_seconds=28_800.0,
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
        prior_investigations: Sequence[Mapping[str, object]] = (),
    ) -> CodeAuditOutcome:
        budget = self._budget
        workspace = AuditWorkspace(self._database, self._store, task_id, limits=self._limits)
        await workspace.load()
        executor = AuditStepExecutor(
            workspace,
            symbolic_runner=self._symbolic_runner,
            dynamic_verification_enabled=(
                self._dynamic_verification_enabled or await self._project_opt_in(task_id)
            ),
        )
        resume_state = await self._load_resume_checkpoint(task_id, job_id)
        loop_resume = _resume_from_state(resume_state, budget) if resume_state else None
        if resume_state is not None:
            resumed_findings = [
                _finding_from_document(item)
                for item in _mapping_items(resume_state.get("reported"))
            ]
            executor.reported.extend(resumed_findings)
            LOGGER.info(
                "audit_resuming_from_checkpoint",
                extra={
                    "job_id": job_id,
                    "rounds": loop_resume.rounds if loop_resume else 0,
                    "steps": len(loop_resume.steps) if loop_resume else 0,
                    "findings": len(resumed_findings),
                },
            )

        async def emit_progress(progress: LoopProgress) -> None:
            await self._save_checkpoint(task_id, job_id, run_id, executor, progress)

        registry = ToolRegistry(AUDIT_TOOLS)
        loop = AgentLoop(
            self._gateway,
            registry,
            PolicyEngine(registry),
            _WorkspaceStepExecutor(executor),
            sink=self._sink,
            tier=ModelTier.AUDIT,
            budget=budget,
            clock=self._clock,
            monotonic=self._monotonic,
            progress=emit_progress if self._checkpoints is not None else None,
        )
        request = AgentLoopRequest(
            task_id=task_id,
            run_id=run_id,
            objective=AUDIT_AGENT_OBJECTIVE,
            context=await self._context(task_id, workspace, prior_investigations),
            policy_context=PolicyContext(
                artifact_kinds=workspace.artifact_kinds,
                permission_mode=PermissionMode.FULL_ACCESS,
            ),
            input_refs=input_refs or workspace.version_ids(),
            instructions=AUDIT_AGENT_INSTRUCTIONS,
            resume=loop_resume,
        )
        result = await loop.run(request)
        fallback: StructuredFailure | None = result.fallback
        return CodeAuditOutcome(
            run=result.agent_run,
            findings=tuple(executor.reported),
            steps=result.steps,
            degraded=result.status is AgentLoopStatus.DEGRADED,
            completed=result.status is AgentLoopStatus.COMPLETED,
            fallback_code=str(fallback["code"]) if fallback is not None else None,
        )

    async def _load_resume_checkpoint(self, task_id: str, job_id: str) -> JsonObject | None:
        """Find the newest interrupted-audit checkpoint for exactly this job.

        A ``completed`` marker means the previous attempt finished the loop
        normally (or degraded and fell back), so a later attempt must not replay
        it.  Checkpoint trouble degrades to a fresh start: resuming is an
        optimization, never a precondition.
        """

        if self._checkpoints is None:
            return None
        try:
            checkpoints = [
                item for item in await self._checkpoints.list(task_id)
                if item.node == AUDIT_CHECKPOINT_NODE
            ]
        except Exception as error:  # a broken checkpoint must never block the audit
            LOGGER.warning(
                "audit_checkpoint_load_failed",
                extra={"task_id": task_id, "error": str(error)[:200]},
            )
            return None
        for checkpoint in reversed(checkpoints):
            state = checkpoint.state
            if state.get("job_id") != job_id:
                continue
            if state.get("completed"):
                return None
            return state
        return None

    async def _save_checkpoint(
        self,
        task_id: str,
        job_id: str,
        run_id: str,
        executor: AuditStepExecutor,
        progress: LoopProgress,
    ) -> None:
        store = self._checkpoints
        if store is None:
            return
        max_chars = self._budget.max_observation_chars
        state: dict[str, object] = {
            "schema_version": "1.0.0",
            "job_id": job_id,
            "run_id": run_id,
            "completed": progress.status is not RunStatus.RUNNING,
            "rounds": progress.round_index,
            "decisions": [dict(record) for record in progress.decisions],
            "steps": [
                _step_document(step, max_chars)
                for step in progress.steps[-_MAX_CHECKPOINT_STEPS:]
            ],
            "last_round_steps": [
                _step_document(step, max_chars) for step in progress.last_round_steps
            ],
            "reported": [
                _finding_document(finding)
                for finding in executor.reported[-_MAX_CHECKPOINT_FINDINGS:]
            ],
            "usage": {
                "input_tokens": progress.usage["input_tokens"],
                "output_tokens": progress.usage["output_tokens"],
            },
            "artifact_refs": list(progress.artifact_refs),
            "model_label": progress.model_label,
        }
        try:
            await store.save(
                task_id, AUDIT_CHECKPOINT_NODE, state, created_at=_now_iso(self._clock)
            )
        except Exception as error:  # checkpointing must never kill the audit
            LOGGER.warning(
                "audit_checkpoint_save_failed",
                extra={"task_id": task_id, "job_id": job_id, "error": str(error)[:200]},
            )

    async def _project_opt_in(self, task_id: str) -> bool:
        """Dynamic validation is a project-level opt-in, resolved per task."""

        async with self._database.transaction() as repositories:
            task = await repositories.tasks.get(task_id)
            project = await repositories.projects.get(task["project_id"])
        return bool(project["exploit_validation_enabled"])

    async def _context(
        self,
        task_id: str,
        workspace: AuditWorkspace,
        prior_investigations: Sequence[Mapping[str, object]] = (),
    ) -> JsonObject:
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
        if prior_investigations:
            context["prior_investigations"] = [
                memory_context_entry(item) for item in prior_investigations
            ]
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


def _now_iso(clock: Callable[[], datetime]) -> str:
    return clock().astimezone(UTC).isoformat().replace("+00:00", "Z")


def _step_document(step: ExecutedStep, max_chars: int) -> JsonObject:
    """JSON shape of one executed step, with its observation bounded.

    The bounded observation is what a resumed run needs: the investigation
    digest bounds it anyway, and unbounded tool outputs would let a checkpoint
    grow with the workspace instead of staying a fixed-cost resume record.
    """

    encoded = json.dumps(step.output, ensure_ascii=False, sort_keys=True)
    output: JsonObject = (
        step.output
        if len(encoded) <= max_chars
        else {"truncated": True, "prefix": encoded[:max_chars]}
    )
    return {
        "step_id": step.step_id,
        "tool_name": step.tool_name,
        "tool_version": step.tool_version,
        "plan_id": step.plan_id,
        "succeeded": step.succeeded,
        "output": output,
        "artifact_refs": list(step.artifact_refs),
        "failure_code": step.failure_code,
    }


def _step_from_document(document: Mapping[str, object]) -> ExecutedStep:
    failure_code = _optional_str(document.get("failure_code"))
    return ExecutedStep(
        step_id=_str_value(document.get("step_id")),
        tool_name=_str_value(document.get("tool_name")) or "unknown",
        tool_version=_str_value(document.get("tool_version")),
        plan_id=_str_value(document.get("plan_id")),
        succeeded=document.get("succeeded") is True,
        output=cast(JsonObject, dict(_mapping_value(document.get("output")))),
        artifact_refs=tuple(
            _str_value(item) for item in _sequence_value(document.get("artifact_refs"))
        ),
        failure_code=failure_code,
    )


def _finding_document(finding: ReportedFinding) -> JsonObject:
    return {
        "cwe_id": finding.cwe_id,
        "title": finding.title,
        "severity": finding.severity,
        "rationale": finding.rationale,
        "path": finding.path,
        "start_line": finding.start_line,
        "end_line": finding.end_line,
        "address": finding.address,
        "verification_request": finding.verification_request,
        "verification_reason": finding.verification_reason,
        "step_id": finding.step_id,
    }


def _finding_from_document(document: Mapping[str, object]) -> ReportedFinding:
    def optional_int(key: str) -> int | None:
        value = document.get(key)
        return value if isinstance(value, int) and not isinstance(value, bool) else None

    return ReportedFinding(
        cwe_id=_str_value(document.get("cwe_id")),
        title=_str_value(document.get("title")),
        severity=_str_value(document.get("severity")) or "unknown",
        rationale=_str_value(document.get("rationale")),
        path=_optional_str(document.get("path")),
        start_line=optional_int("start_line"),
        end_line=optional_int("end_line"),
        address=optional_int("address"),
        verification_request=_optional_str(document.get("verification_request")),
        verification_reason=_optional_str(document.get("verification_reason")),
        step_id=_str_value(document.get("step_id")),
    )


def _resume_from_state(state: Mapping[str, object], budget: AgentLoopBudget) -> LoopResume:
    usage = _mapping_value(state.get("usage"))
    return LoopResume(
        decisions=tuple(
            DecisionRecord(
                sequence=_int_value(item.get("sequence")),
                decision=_str_value(item.get("decision")),
                reason=_str_value(item.get("reason")),
                created_at=_str_value(item.get("created_at")),
            )
            for item in _mapping_items(state.get("decisions"))
        ),
        steps=tuple(
            _step_from_document(item)
            for item in _mapping_items(state.get("steps"))
        ),
        last_round_steps=tuple(
            _step_from_document(item)
            for item in _mapping_items(state.get("last_round_steps"))
        ),
        usage=TokenUsage(
            input_tokens=_int_value(usage.get("input_tokens")),
            output_tokens=_int_value(usage.get("output_tokens")),
        ),
        artifact_refs=tuple(
            _str_value(item) for item in _sequence_value(state.get("artifact_refs"))
        ),
        model_label=_optional_str(state.get("model_label")),
        rounds=_int_value(state.get("rounds")),
    )


def _mapping_value(value: object) -> Mapping[str, object]:
    if isinstance(value, dict):
        return cast(Mapping[str, object], value)
    return {}


def _mapping_items(value: object) -> list[Mapping[str, object]]:
    """Every mapping entry of a JSON list, skipping anything else."""

    if not isinstance(value, (list, tuple)):
        return []
    return [
        cast(Mapping[str, object], item)
        for item in cast(list[object], value)
        if isinstance(item, Mapping)
    ]


def _sequence_value(value: object) -> list[object]:
    return cast(list[object], value) if isinstance(value, list) else []


def _int_value(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _str_value(value: object) -> str:
    return value if isinstance(value, str) else ""


def _optional_str(value: object) -> str | None:
    return value if isinstance(value, str) and value else None



__all__ = [
    "AUDIT_AGENT_INSTRUCTIONS",
    "AUDIT_AGENT_OBJECTIVE",
    "AUDIT_CHECKPOINT_NODE",
    "AuditProgressSink",
    "CodeAuditAgent",
    "CodeAuditOutcome",
    "audit_run_id",
]
