from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import cast

import pytest
from vulnweaver_contracts import (
    AgentRun,
    ArtifactKind,
    DecisionRecord,
    FailureKind,
    JsonObject,
    PermissionMode,
    ResourceBudget,
    RunStatus,
    StructuredFailure,
    TokenUsage,
)
from vulnweaver_model_gateway import ModelCallResult
from vulnweaver_orchestrator import (
    AgentLoop,
    AgentLoopBudget,
    AgentLoopRequest,
    AgentLoopStatus,
    ExecutedStep,
    LoopResume,
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


def run_stub(*, model: str = "planning:test-model", tokens: tuple[int, int] = (10, 10)) -> AgentRun:
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
    executor = RecordingExecutor([StepOutcome(True, {"findings": 0}, artifact_refs=("derived:1",))])
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
    # The loop may flush a progress snapshot per round; every write is the
    # same aggregated run, and the last one carries the terminal status.
    assert {run["id"] for run in sink.runs} == {"agent-run:loop:1"}
    assert sink.runs[-1]["status"] is RunStatus.SUCCEEDED
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


def test_model_token_usage_never_stops_the_loop() -> None:
    asyncio.run(_model_token_usage_never_stops_the_loop())


async def _model_token_usage_never_stops_the_loop() -> None:
    # Token usage is recorded and reported, but it is not a budget. A lifetime
    # bound counted in tokens describes one call's context window, and stopping a
    # multi-round investigation on it cuts the work off part-way through.
    planner = FakePlanner(
        [
            ModelCallResult(
                model_proposal([]), run_stub(tokens=(900_000, 900_000)), None, "endpoint-1"
            )
        ]
    )

    result = await build_loop(planner, RecordingExecutor([])).run(loop_request())

    assert result.status is AgentLoopStatus.COMPLETED
    assert result.fallback is None
    assert result.agent_run["token_usage"]["input_tokens"] == 900_000


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
    planner = FakePlanner([failed("model_transport_error"), failed("model_transport_error")])
    budget = AgentLoopBudget(max_consecutive_model_failures=2)

    result = await build_loop(planner, RecordingExecutor([]), budget=budget).run(loop_request())

    assert result.status is AgentLoopStatus.DEGRADED
    assert result.fallback is not None
    assert result.fallback["code"] == "model_repeated_failure"


def test_single_model_failure_is_retried_by_the_loop() -> None:
    asyncio.run(_single_model_failure_is_retried_by_the_loop())


async def _single_model_failure_is_retried_by_the_loop() -> None:
    planner = FakePlanner([failed("model_transport_error"), succeeded(model_proposal([]))])

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
    executor = RecordingExecutor([StepOutcome(False, {}, failure_code="tool_execution_failed")])

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


def _resumed_step(step_id: str = "step:1") -> ExecutedStep:
    return ExecutedStep(
        step_id=step_id,
        tool_name="semgrep",
        tool_version="1.0.0",
        plan_id="agent-run:loop:1-plan-1",
        succeeded=True,
        output={"findings": 1},
        artifact_refs=("version:1",),
        failure_code=None,
    )


def _resume_state(rounds: int = 1) -> LoopResume:

    step = _resumed_step()
    decisions = [
        DecisionRecord(
            sequence=1,
            decision="plan_accepted",
            reason="prior attempt approved one step",
            created_at=NOW.isoformat(),
        ),
        DecisionRecord(
            sequence=2,
            decision="step_executed",
            reason="step step:1 via semgrep",
            created_at=NOW.isoformat(),
        ),
    ]
    return LoopResume(
        decisions=tuple(decisions),
        steps=(step,),
        last_round_steps=(step,),
        usage=TokenUsage(input_tokens=101, output_tokens=37),
        artifact_refs=("version:1",),
        model_label="audit:deepseek-flash",
        rounds=rounds,
    )


def test_resume_seeds_history_and_skips_reexecution() -> None:
    planner = FakePlanner([succeeded(model_proposal([]))])
    executor = RecordingExecutor([])
    loop = build_loop(planner, executor)
    request = AgentLoopRequest(
        task_id="task:1",
        run_id="agent-run:loop:1",
        objective="analyze the sample",
        context={"artifact": "version:1"},
        policy_context=full_access_context(),
        input_refs=("version:1",),
        resume=_resume_state(),
    )
    result = asyncio.run(loop.run(request))

    assert executor.calls == []  # resumed steps are never re-executed
    assert result.status is AgentLoopStatus.COMPLETED
    assert [step.step_id for step in result.steps] == ["step:1"]
    decisions = result.agent_run["decisions"]
    assert len(decisions) == 3
    assert [record["sequence"] for record in decisions] == [1, 2, 3]
    # Usage accumulates from the resumed attempt, not reset to zero.
    assert result.agent_run["token_usage"]["input_tokens"] >= 101
    # The model's first message on the resumed run must show the prior round.
    first_round_messages = planner.messages[0]
    encoded = json.dumps(first_round_messages)
    assert "planning_round" in encoded


def test_resume_rejects_inconsistent_state() -> None:
    from vulnweaver_orchestrator import LoopResume

    with pytest.raises(ValueError):
        LoopResume(
            decisions=(),
            steps=(),
            last_round_steps=(),
            usage={"input_tokens": 0, "output_tokens": 0},
            artifact_refs=(),
            model_label=None,
            rounds=1,
        )
    with pytest.raises(ValueError):
        LoopResume(
            decisions=_resume_state().decisions,
            steps=(_resumed_step(),),
            last_round_steps=(),
            usage={"input_tokens": 0, "output_tokens": 0},
            artifact_refs=(),
            model_label=None,
            rounds=0,
        )


def test_progress_callback_emits_running_and_terminal_snapshots() -> None:
    from vulnweaver_orchestrator import LoopProgress

    planner = FakePlanner(
        [succeeded(model_proposal([scan_step("step:1")])), succeeded(model_proposal([]))]
    )
    executor = RecordingExecutor(
        [StepOutcome(succeeded=True, output={"findings": 0}, artifact_refs=(), failure_code=None)]
    )
    emitted: list[LoopProgress] = []

    async def progress(value: LoopProgress) -> None:
        emitted.append(value)

    loop = AgentLoop(
        planner,
        ToolRegistry([spec()]),
        PolicyEngine(ToolRegistry([spec()])),
        executor,
        budget=AgentLoopBudget(deadline_seconds=30),
        clock=clock,
        monotonic=monotonic,
        progress=progress,
    )
    result = asyncio.run(loop.run(loop_request()))

    assert result.status is AgentLoopStatus.COMPLETED
    assert [item.status for item in emitted] == [RunStatus.RUNNING, RunStatus.SUCCEEDED]
    assert emitted[0].round_index == 1
    assert [item.step_id for item in emitted[0].last_round_steps] == ["step:1"]
    # The compacted journal rides along so a checkpoint can restore it.
    assert [entry["round"] for entry in emitted[0].journal] == [1]
    assert emitted[-1].steps == result.steps
    assert emitted[-1].decisions == tuple(result.agent_run["decisions"])


def test_journal_feeds_older_rounds_without_duplicating_feedback() -> None:
    asyncio.run(_journal_feeds_older_rounds_without_duplicating_feedback())


async def _journal_feeds_older_rounds_without_duplicating_feedback() -> None:
    planner = FakePlanner(
        [
            succeeded(model_proposal([scan_step("step:1")])),
            succeeded(model_proposal([scan_step("step:2")])),
            succeeded(model_proposal([])),
        ]
    )
    executor = RecordingExecutor(
        [
            StepOutcome(True, {"summary": "first round observation"}),
            StepOutcome(True, {"summary": "second round observation"}),
        ]
    )

    result = await build_loop(planner, executor).run(loop_request())

    assert result.status is AgentLoopStatus.COMPLETED
    third_user = json.loads(planner.messages[2][1]["content"])
    # Round 2 stays verbatim in last_feedback; only round 1 is compacted into
    # the journal, so the prompt never carries the same round twice.
    journal = third_user["investigation_journal"]
    assert [entry["round"] for entry in journal] == [1]
    assert journal[0]["kind"] == "step"
    assert journal[0]["tool"] == "semgrep@1.0.0"
    assert journal[0]["outcome"] == "ok"
    assert journal[0]["summary"] == "first round observation"
    assert third_user["last_feedback"]["planning_round"] == 2
    assert third_user["last_feedback"]["last_steps"][0]["output"] == {
        "summary": "second round observation"
    }


def test_journal_is_bounded_and_ages_out_oldest_first() -> None:
    asyncio.run(_journal_is_bounded_and_ages_out_oldest_first())


async def _journal_is_bounded_and_ages_out_oldest_first() -> None:
    planner = FakePlanner(
        [succeeded(model_proposal([scan_step(f"step:{index}")])) for index in range(1, 4)]
        + [succeeded(model_proposal([]))]
    )
    executor = RecordingExecutor(
        [StepOutcome(True, {"summary": f"round {index} observation"}) for index in range(1, 4)]
    )
    budget = AgentLoopBudget(max_journal_entries=2)

    result = await build_loop(planner, executor, budget=budget).run(loop_request())

    assert result.status is AgentLoopStatus.COMPLETED
    fourth_user = json.loads(planner.messages[3][1]["content"])
    # After round 3 the journal held rounds 2 and 3; round 3 moved into
    # last_feedback, leaving exactly one compacted entry.
    assert [entry["round"] for entry in fourth_user["investigation_journal"]] == [2]
    assert fourth_user["investigation_journal"][0]["summary"] == "round 2 observation"


def test_journal_can_be_disabled() -> None:
    asyncio.run(_journal_can_be_disabled())


async def _journal_can_be_disabled() -> None:
    planner = FakePlanner(
        [
            succeeded(model_proposal([scan_step()])),
            succeeded(model_proposal([])),
        ]
    )
    executor = RecordingExecutor([StepOutcome(True, {"findings": 0})])
    budget = AgentLoopBudget(max_journal_entries=0)

    result = await build_loop(planner, executor, budget=budget).run(loop_request())

    assert result.status is AgentLoopStatus.COMPLETED
    second_user = json.loads(planner.messages[1][1]["content"])
    assert "investigation_journal" not in second_user
    # The last round still arrives verbatim.
    assert second_user["last_feedback"]["last_steps"][0]["output"] == {"findings": 0}


def test_plan_rejections_enter_the_journal() -> None:
    asyncio.run(_plan_rejections_enter_the_journal())


async def _plan_rejections_enter_the_journal() -> None:
    bad_step = dict(scan_step())
    bad_step["tool_name"] = "unregistered-tool"
    planner = FakePlanner(
        [
            succeeded(model_proposal([cast(JsonObject, bad_step)])),
            succeeded(model_proposal([scan_step("step:2")])),
            succeeded(model_proposal([])),
        ]
    )
    executor = RecordingExecutor([StepOutcome(True, {"findings": 1})])

    result = await build_loop(planner, executor).run(loop_request())

    assert result.status is AgentLoopStatus.COMPLETED
    third_user = json.loads(planner.messages[2][1]["content"])
    journal = third_user["investigation_journal"]
    # The round-2 step moved into last_feedback; the rejection is what stays.
    assert journal == [{"round": 1, "kind": "plan_rejected", "reasons": ["tool_not_registered"]}]


def test_journal_entry_summaries_are_single_line_and_bounded() -> None:
    asyncio.run(_journal_entry_summaries_are_single_line_and_bounded())


async def _journal_entry_summaries_are_single_line_and_bounded() -> None:
    planner = FakePlanner(
        [
            succeeded(model_proposal([scan_step("step:1")])),
            succeeded(model_proposal([scan_step("step:2")])),
            succeeded(model_proposal([])),
        ]
    )
    executor = RecordingExecutor(
        [
            StepOutcome(True, {"summary": "line one\nline two\n" + "x" * 500}),
            StepOutcome(True, {"findings": 0}),
        ]
    )
    budget = AgentLoopBudget(max_journal_entry_chars=64)

    result = await build_loop(planner, executor, budget=budget).run(loop_request())

    assert result.status is AgentLoopStatus.COMPLETED
    third_user = json.loads(planner.messages[2][1]["content"])
    summary = str(third_user["investigation_journal"][0]["summary"])
    # Newlines collapse and the digest respects its own char cap, so one entry
    # can never blow the prompt line budget.
    assert "\n" not in summary
    assert len(summary) <= 64
    assert summary.startswith("line one line two")


def test_resume_seeds_the_journal() -> None:
    asyncio.run(_resume_seeds_the_journal())


async def _resume_seeds_the_journal() -> None:
    seeded = (
        {
            "round": 1,
            "kind": "step",
            "step_id": "step:0",
            "tool": "semgrep@1.0.0",
            "outcome": "ok",
            "summary": "prior digest",
        },
        {
            "round": 2,
            "kind": "step",
            "step_id": "step:1",
            "tool": "semgrep@1.0.0",
            "outcome": "ok",
            "summary": "same round as last_feedback",
        },
    )
    resume = replace(_resume_state(rounds=2), journal=seeded)
    planner = FakePlanner([succeeded(model_proposal([]))])
    executor = RecordingExecutor([])
    request = AgentLoopRequest(
        task_id="task:1",
        run_id="agent-run:loop:1",
        objective="analyze the sample",
        context={"artifact": "version:1"},
        policy_context=full_access_context(),
        input_refs=("version:1",),
        resume=resume,
    )

    result = await build_loop(planner, executor).run(request)

    assert result.status is AgentLoopStatus.COMPLETED
    first_user = json.loads(planner.messages[0][1]["content"])
    # The round already covered by last_feedback is filtered; older history
    # survives the crash.
    assert [entry["summary"] for entry in first_user["investigation_journal"]] == ["prior digest"]
    assert first_user["last_feedback"]["planning_round"] == 2


def test_budget_rejects_invalid_journal_bounds() -> None:
    with pytest.raises(ValueError):
        AgentLoopBudget(max_journal_entries=-1)
    with pytest.raises(ValueError):
        AgentLoopBudget(max_journal_entry_chars=16)
