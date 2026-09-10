from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import cast

import pytest
from vulnweaver_contracts import (
    AgentRun,
    ArtifactKind,
    FailureKind,
    JsonObject,
    PermissionMode,
    ResourceBudget,
    RunStatus,
    StructuredFailure,
)
from vulnweaver_model_gateway import ModelCallResult
from vulnweaver_orchestrator import (
    AgentLoop,
    AgentLoopBudget,
    AgentLoopRequest,
    AgentLoopStatus,
    StepOutcome,
)
from vulnweaver_tool_runtime import PolicyContext, PolicyEngine, ScheduledToolCall, ToolRegistry

NOW = datetime(2026, 9, 10, 8, 0, tzinfo=UTC)
TICKS = iter(range(1, 10_000))


def monotonic() -> float:
    return next(TICKS) / 1_000


def clock() -> datetime:
    return NOW


def budget_limits() -> ResourceBudget:
    return cast(
        ResourceBudget,
        {
            "max_model_tokens": 10_000,
            "cpu_millis": 2_000,
            "memory_bytes": 128 * 1024 * 1024,
            "disk_bytes": 256 * 1024 * 1024,
            "max_tool_concurrency": 4,
            "max_dynamic_runs": 2,
            "timeout_seconds": 120,
        },
    )


def spec(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": "1.0.0",
        "name": "semgrep",
        "version": "1.0.0",
        "image_digest": "sha256:" + "a" * 64,
        "risk_level": "low",
        "accepted_artifacts": ["source_archive"],
        "command_schema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["ruleset"],
            "properties": {"ruleset": {"type": "string", "minLength": 1}},
        },
        "output_schema": {"type": "object"},
        "network_policy": {"access": "none", "allowed_hosts": []},
        "filesystem_policy": {
            "input_read_only": True,
            "isolated_output": True,
            "allow_host_paths": False,
        },
        "resource_limits": budget_limits(),
        "approval_required": False,
        "timeout_seconds": 60,
        "retry_policy": {
            "max_attempts": 2,
            "backoff_seconds": 1,
            "retryable_failure_kinds": ["timeout", "environment"],
        },
    }
    value.update(overrides)
    return value


def model_proposal(steps: list[JsonObject]) -> JsonObject:
    """Shape a planner proposal exactly as the model would emit it."""
    return cast(
        JsonObject,
        {
            "schema_version": "1.0.0",
            "steps": steps,
            "rationale": "model reasoning for this round",
        },
    )


def scan_step(step_id: str = "step:1") -> JsonObject:
    return cast(
        JsonObject,
        {
            "step_id": step_id,
            "tool_name": "semgrep",
            "tool_version": "1.0.0",
            "input_refs": ["version:1"],
            "arguments": {"ruleset": "safe-default"},
            "expected_output_types": ["sarif"],
            "reason": "scan the registered source",
        },
    )


def run_stub(
    *, model: str = "planning:test-model", tokens: tuple[int, int] = (10, 10)
) -> AgentRun:
    return cast(
        AgentRun,
        {
            "schema_version": "1.0.0",
            "id": "agent-run:stub",
            "task_id": "task:1",
            "status": RunStatus.SUCCEEDED,
            "model": model,
            "prompt_hash": "0" * 64,
            "input_refs": [],
            "decisions": [],
            "token_usage": {"input_tokens": tokens[0], "output_tokens": tokens[1]},
            "failure": None,
            "created_at": NOW.isoformat(),
            "updated_at": NOW.isoformat(),
        },
    )


def failure_stub(code: str) -> StructuredFailure:
    return StructuredFailure(
        code=code,
        kind=FailureKind.DEPENDENCY,
        message="planning failed",
        retryable=False,
        details={},
    )


def full_access_context() -> PolicyContext:
    return PolicyContext(
        artifact_kinds={"version:1": ArtifactKind.SOURCE_ARCHIVE},
        resource_budget=budget_limits(),
        permission_mode=PermissionMode.FULL_ACCESS,
    )


def loop_request() -> AgentLoopRequest:
    return AgentLoopRequest(
        task_id="task:1",
        run_id="agent-run:loop:1",
        objective="analyze the sample",
        context={"artifact": "version:1"},
        policy_context=full_access_context(),
        input_refs=("version:1",),
    )


@dataclass
class FakePlanner:
    """Scripted PlannerGateway returning queued responses in order."""

    responses: list[ModelCallResult]
    messages: list[list[dict[str, str]]] = field(default_factory=list)

    async def complete_structured(self, **kwargs: object) -> ModelCallResult:
        self.messages.append(cast(list[dict[str, str]], kwargs["messages"]))
        return self.responses.pop(0)


@dataclass
class RecordingExecutor:
    outcomes: list[StepOutcome]
    calls: list[ScheduledToolCall] = field(default_factory=list)

    async def execute(self, call: ScheduledToolCall) -> StepOutcome:
        self.calls.append(call)
        return self.outcomes.pop(0)


@dataclass
class Sink:
    runs: list[AgentRun] = field(default_factory=list)

    async def add(self, run: AgentRun) -> None:
        self.runs.append(run)


def build_loop(
    planner: FakePlanner,
    executor: RecordingExecutor,
    *,
    sink: Sink | None = None,
    budget: AgentLoopBudget | None = None,
) -> AgentLoop:
    return AgentLoop(
        planner,
        ToolRegistry([spec()]),
        PolicyEngine(ToolRegistry([spec()])),
        executor,
        sink=sink,
        budget=budget,
        clock=clock,
        monotonic=monotonic,
    )


def succeeded(output: JsonObject) -> ModelCallResult:
    return ModelCallResult(output, run_stub(), None, "endpoint-1")


def failed(code: str) -> ModelCallResult:
    return ModelCallResult(None, run_stub(), failure_stub(code), None)


def test_loop_executes_steps_until_empty_plan() -> None:
    asyncio.run(_loop_executes_steps_until_empty_plan())


async def _loop_executes_steps_until_empty_plan() -> None:
    planner = FakePlanner(
        [
            succeeded(model_proposal([scan_step()])),
            succeeded(model_proposal([])),
        ]
    )
    executor = RecordingExecutor(
        [StepOutcome(True, {"findings": 0}, artifact_refs=("derived:1",))]
    )
    sink = Sink()

    result = await build_loop(planner, executor, sink=sink).run(loop_request())

    assert result.status is AgentLoopStatus.COMPLETED
    assert not result.degraded
    assert result.fallback is None
    assert [call.step_id for call in executor.calls] == ["step:1"]
    assert result.steps[0].succeeded
    assert result.agent_run["status"] is RunStatus.SUCCEEDED
    assert [record["decision"] for record in result.agent_run["decisions"]] == [
        "plan_accepted",
        "step_executed",
        "loop_completed",
    ]
    assert result.agent_run["result_refs"] == ["derived:1"]
    assert [run["id"] for run in sink.runs] == ["agent-run:loop:1"]
    # The next observation carries the bounded result of the executed step.
    second_user = json.loads(planner.messages[1][1]["content"])
    assert second_user["last_feedback"]["last_steps"][0]["output"] == {"findings": 0}


def test_model_identity_fields_are_overridden() -> None:
    asyncio.run(_model_identity_fields_are_overridden())


async def _model_identity_fields_are_overridden() -> None:
    planner = FakePlanner(
        [
            succeeded(model_proposal([scan_step()])),
            succeeded(model_proposal([])),
        ]
    )
    executor = RecordingExecutor([StepOutcome(True, {"findings": 0})])

    result = await build_loop(planner, executor).run(loop_request())

    assert result.status is AgentLoopStatus.COMPLETED
    assert result.plans[0]["id"] == "agent-run:loop:1-plan-1"
    assert result.plans[0]["task_id"] == "task:1"
    assert result.plans[0]["agent_run_id"] == "agent-run:loop:1"
    assert result.plans[0]["created_at"] == NOW.isoformat().replace("+00:00", "Z")


def test_policy_rejected_plan_is_fed_back_then_accepted() -> None:
    asyncio.run(_policy_rejected_plan_is_fed_back_then_accepted())


async def _policy_rejected_plan_is_fed_back_then_accepted() -> None:
    bad_step = dict(scan_step())
    bad_step["tool_name"] = "unregistered-tool"
    planner = FakePlanner(
        [
            succeeded(model_proposal([cast(JsonObject, bad_step)])),
            succeeded(model_proposal([scan_step()])),
            succeeded(model_proposal([])),
        ]
    )
    executor = RecordingExecutor([StepOutcome(True, {"findings": 1})])

    result = await build_loop(planner, executor).run(loop_request())

    assert result.status is AgentLoopStatus.COMPLETED
    decisions = [record["decision"] for record in result.agent_run["decisions"]]
    assert decisions[0] == "plan_rejected"
    assert len(executor.calls) == 1
    feedback = json.loads(planner.messages[1][1]["content"])["last_feedback"]
    assert feedback["plan_rejected_reasons"] == ["tool_not_registered"]


def test_repeated_policy_rejection_degrades_to_fixed_pipeline() -> None:
    asyncio.run(_repeated_policy_rejection_degrades_to_fixed_pipeline())


async def _repeated_policy_rejection_degrades_to_fixed_pipeline() -> None:
    bad_step = dict(scan_step())
    bad_step["tool_name"] = "unregistered-tool"
    planner = FakePlanner(
        [succeeded(model_proposal([cast(JsonObject, bad_step)])) for _ in range(4)]
    )

    result = await build_loop(planner, RecordingExecutor([])).run(loop_request())

    assert result.status is AgentLoopStatus.DEGRADED
    assert result.degraded
    assert result.fallback is not None
    assert result.fallback["code"] == "plan_repeatedly_rejected"
    assert result.fallback["kind"] is FailureKind.POLICY
    assert result.agent_run["status"] is RunStatus.FAILED
    assert "degraded_to_fixed_pipeline" in [
        record["decision"] for record in result.agent_run["decisions"]
    ]


def test_planning_round_budget_exhaustion() -> None:
    asyncio.run(_planning_round_budget_exhaustion())


async def _planning_round_budget_exhaustion() -> None:
    planner = FakePlanner([succeeded(model_proposal([scan_step()])) for _ in range(3)])
    executor = RecordingExecutor([StepOutcome(True, {"findings": 0}) for _ in range(3)])
    budget = AgentLoopBudget(max_planning_rounds=2)

    result = await build_loop(planner, executor, budget=budget).run(loop_request())

    assert result.status is AgentLoopStatus.BUDGET_EXHAUSTED
    assert result.fallback is not None
    assert result.fallback["code"] == "loop_planning_round_budget_exhausted"
    assert len(planner.messages) == 2


def test_model_token_budget_exhaustion() -> None:
    asyncio.run(_model_token_budget_exhaustion())


async def _model_token_budget_exhaustion() -> None:
    planner = FakePlanner(
        [ModelCallResult(model_proposal([]), run_stub(tokens=(900, 900)), None, "endpoint-1")]
    )
    budget = AgentLoopBudget(max_model_tokens=1_000)

    result = await build_loop(planner, RecordingExecutor([]), budget=budget).run(loop_request())

    assert result.status is AgentLoopStatus.BUDGET_EXHAUSTED
    assert result.fallback is not None
    assert result.fallback["code"] == "loop_model_token_budget_exhausted"


def test_unconfigured_model_degrades_immediately() -> None:
    asyncio.run(_unconfigured_model_degrades_immediately())


async def _unconfigured_model_degrades_immediately() -> None:
    planner = FakePlanner([failed("model_configuration_error")])

    result = await build_loop(planner, RecordingExecutor([])).run(loop_request())

    assert result.status is AgentLoopStatus.DEGRADED
    assert result.fallback is not None
    assert result.fallback["code"] == "model_unconfigured"
    assert result.fallback["kind"] is FailureKind.DEPENDENCY
    assert result.agent_run["model"] == "planning:test-model"
    assert len(planner.messages) == 1


def test_repeated_model_failures_degrade() -> None:
    asyncio.run(_repeated_model_failures_degrade())


async def _repeated_model_failures_degrade() -> None:
    planner = FakePlanner(
        [failed("model_transport_error"), failed("model_transport_error")]
    )
    budget = AgentLoopBudget(max_consecutive_model_failures=2)

    result = await build_loop(planner, RecordingExecutor([]), budget=budget).run(loop_request())

    assert result.status is AgentLoopStatus.DEGRADED
    assert result.fallback is not None
    assert result.fallback["code"] == "model_repeated_failure"


def test_single_model_failure_is_retried_by_the_loop() -> None:
    asyncio.run(_single_model_failure_is_retried_by_the_loop())


async def _single_model_failure_is_retried_by_the_loop() -> None:
    planner = FakePlanner(
        [failed("model_transport_error"), succeeded(model_proposal([]))]
    )

    result = await build_loop(planner, RecordingExecutor([])).run(loop_request())

    assert result.status is AgentLoopStatus.COMPLETED
    assert len(planner.messages) == 2


def test_waiting_permission_stops_the_loop() -> None:
    asyncio.run(_waiting_permission_stops_the_loop())


async def _waiting_permission_stops_the_loop() -> None:
    planner = FakePlanner([succeeded(model_proposal([scan_step()]))])
    approval_spec = spec(approval_required=True)
    request = AgentLoopRequest(
        task_id="task:1",
        run_id="agent-run:loop:1",
        objective="analyze the sample",
        context={"artifact": "version:1"},
        policy_context=PolicyContext(
            artifact_kinds={"version:1": ArtifactKind.SOURCE_ARCHIVE},
            resource_budget=budget_limits(),
            permission_mode=PermissionMode.REQUEST_PERMISSION,
        ),
        input_refs=("version:1",),
    )

    loop = AgentLoop(
        planner,
        ToolRegistry([approval_spec]),
        PolicyEngine(ToolRegistry([approval_spec])),
        RecordingExecutor([]),
        clock=clock,
        monotonic=monotonic,
    )
    result = await loop.run(request)

    assert result.status is AgentLoopStatus.WAITING_PERMISSION
    assert result.plans
    assert result.steps == ()
    assert result.fallback is not None
    assert result.fallback["code"] == "loop_waiting_permission"
    assert result.fallback["retryable"] is True


def test_failed_step_is_observed_by_the_next_round() -> None:
    asyncio.run(_failed_step_is_observed_by_the_next_round())


async def _failed_step_is_observed_by_the_next_round() -> None:
    planner = FakePlanner(
        [
            succeeded(model_proposal([scan_step()])),
            succeeded(model_proposal([])),
        ]
    )
    executor = RecordingExecutor(
        [StepOutcome(False, {}, failure_code="tool_execution_failed")]
    )

    result = await build_loop(planner, executor).run(loop_request())

    assert result.status is AgentLoopStatus.COMPLETED
    assert result.steps[0].succeeded is False
    decisions = [record["decision"] for record in result.agent_run["decisions"]]
    assert "step_failed" in decisions
    feedback = json.loads(planner.messages[1][1]["content"])["last_feedback"]
    assert feedback["last_steps"][0]["failure_code"] == "tool_execution_failed"


def test_step_limit_violation_is_reported_to_the_model() -> None:
    asyncio.run(_step_limit_violation_is_reported_to_the_model())


async def _step_limit_violation_is_reported_to_the_model() -> None:
    oversized = model_proposal([scan_step(f"step:{index}") for index in range(1, 4)])
    budget = AgentLoopBudget(max_steps_per_plan=2)
    planner = FakePlanner(
        [
            succeeded(oversized),
            succeeded(model_proposal([scan_step()])),
            succeeded(model_proposal([])),
        ]
    )
    executor = RecordingExecutor([StepOutcome(True, {"findings": 0})])

    result = await build_loop(planner, executor, budget=budget).run(loop_request())

    assert result.status is AgentLoopStatus.COMPLETED
    feedback = json.loads(planner.messages[1][1]["content"])["last_feedback"]
    assert feedback["plan_rejected_reasons"] == ["plan_step_limit_exceeded"]
    assert len(executor.calls) == 1


def test_large_step_output_is_truncated_in_the_observation() -> None:
    asyncio.run(_large_step_output_is_truncated_in_the_observation())


async def _large_step_output_is_truncated_in_the_observation() -> None:
    planner = FakePlanner(
        [
            succeeded(model_proposal([scan_step()])),
            succeeded(model_proposal([])),
        ]
    )
    executor = RecordingExecutor([StepOutcome(True, {"blob": "x" * 40_000})])
    budget = AgentLoopBudget(max_observation_chars=512)

    result = await build_loop(planner, executor, budget=budget).run(loop_request())

    assert result.status is AgentLoopStatus.COMPLETED
    feedback = json.loads(planner.messages[1][1]["content"])["last_feedback"]
    bounded = feedback["last_steps"][0]["output"]
    assert bounded["truncated"] is True
    assert len(cast(str, bounded["prefix"])) == 512


def test_budget_rejects_invalid_bounds() -> None:
    with pytest.raises(ValueError):
        AgentLoopBudget(max_planning_rounds=0)
    with pytest.raises(ValueError):
        AgentLoopBudget(deadline_seconds=0)


def test_request_rejects_missing_identity() -> None:
    with pytest.raises(ValueError):
        AgentLoopRequest(
            task_id="",
            run_id="agent-run:loop:1",
            objective="analyze",
            context={},
            policy_context=full_access_context(),
        )
    with pytest.raises(ValueError):
        AgentLoopRequest(
            task_id="task:1",
            run_id="agent-run:loop:1",
            objective="",
            context={},
            policy_context=full_access_context(),
        )
