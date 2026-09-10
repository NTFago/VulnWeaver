from __future__ import annotations

import asyncio
from typing import Any, cast
from uuid import uuid4

from vulnweaver_contracts import AgentRun, RunStatus, StructuredFailure
from vulnweaver_model_gateway import ModelCallResult
from vulnweaver_orchestrator import (
    DatabaseAgentRunSink,
    ReversePlanningAgent,
)
from vulnweaver_persistence import Database, DatabaseSettings

from tests.persistence.factories import artifact, artifact_version, project, task

TIMESTAMP = "2026-09-10T08:00:00Z"


class FakePlannerModel:
    def __init__(self, responses: list[ModelCallResult]) -> None:
        self._responses = responses
        self.messages: list[list[dict[str, str]]] = []

    async def complete_structured(self, **kwargs: object) -> ModelCallResult:
        self.messages.append(cast(list[dict[str, str]], kwargs["messages"]))
        return self._responses.pop(0)


def run_stub(observed: dict[str, object]) -> object:
    async def run_angr(target_addresses: tuple[int, ...]) -> dict[str, object]:
        return {**observed, "targets": list(target_addresses)}

    return run_angr


def model_result(steps: list[dict[str, object]]) -> ModelCallResult:
    agent_run = cast(
        AgentRun,
        {
            "schema_version": "1.0.0",
            "id": "agent-run:stub",
            "task_id": "task:1",
            "status": RunStatus.SUCCEEDED,
            "model": "planning/test",
            "prompt_hash": "sha256:" + "a" * 64,
            "input_refs": [],
            "decisions": [],
            "token_usage": {"input_tokens": 5, "output_tokens": 5},
            "failure": None,
            "created_at": TIMESTAMP,
            "updated_at": TIMESTAMP,
        },
    )
    proposal = {
        "schema_version": "1.0.0",
        "steps": steps,
        "rationale": "dispatcher-like functions need symbolic execution",
    }
    return ModelCallResult(proposal, agent_run, None, "endpoint-1")


def angr_step(addresses: list[int], input_ref: str) -> dict[str, object]:
    return {
        "step_id": "step:angr",
        "tool_name": "angr-targeted-analysis",
        "tool_version": "1.0.0",
        "input_refs": [input_ref],
        "arguments": {"addresses": addresses, "reason": "flattened dispatcher"},
        "expected_output_types": ["symbolic_facts"],
        "reason": "target the dispatcher function",
    }


def facts() -> dict[str, object]:
    return {
        "input_artifact_version_id": "artifact-version:1",
        "packed": False,
        "packer": None,
        "function_count": 3,
        "functions": [{"name": "dispatcher", "address": 4196100}],
        "obfuscation": [
            {
                "function_name": "dispatcher",
                "flattened": True,
                "score": 0.9,
                "dispatcher_blocks": 6,
                "indirect_jumps": 4,
                "reason": "dispatcher block cluster",
            }
        ],
        "basic_block_count": 12,
        "xref_count": 7,
        "pseudocode_count": 0,
    }


class Sink:
    def __init__(self) -> None:
        self.runs: list[AgentRun] = []

    async def add(self, run: AgentRun) -> None:
        self.runs.append(run)


def test_planning_agent_executes_angr_and_collects_targets() -> None:
    async def scenario() -> None:
        model = FakePlannerModel(
            [
                model_result([angr_step([4196100], "artifact-version:1")]),
                model_result([]),
            ]
        )
        sink = Sink()
        agent = ReversePlanningAgent(model, database=cast(Any, None), sink=cast(Any, sink))
        runner_calls: list[tuple[int, ...]] = []

        async def run_angr(targets: tuple[int, ...]) -> dict[str, object]:
            runner_calls.append(targets)
            return {"status": "completed", "targets": list(targets), "symbolic_facts": 3}

        planned = await agent.plan(
            task_id="task:1", job_id="job:1", facts=facts(), run_angr=run_angr  # type: ignore[arg-type]
        )
        assert planned.degraded is False
        assert planned.targets == (4196100,)
        assert runner_calls == [(4196100,)]
        assert planned.agent_run["status"] == "succeeded"
        decisions = [record["decision"] for record in planned.agent_run["decisions"]]
        assert decisions == ["plan_accepted", "step_executed", "loop_completed"]
        assert [run["id"] for run in sink.runs] == ["agent-run:reverse-plan:job:1"]

    asyncio.run(scenario())


def test_planning_agent_degrades_when_model_fails() -> None:
    async def scenario() -> None:
        failure = StructuredFailure(
            code="model_configuration_error",
            kind="dependency",
            message="unconfigured",
            retryable=False,
            details={},
        )
        model = FakePlannerModel(
            [ModelCallResult(None, model_result([]).agent_run, failure, None)]
        )
        agent = ReversePlanningAgent(model, database=cast(Any, None))

        async def run_angr(targets: tuple[int, ...]) -> dict[str, object]:
            return {"targets": list(targets)}

        planned = await agent.plan(
            task_id="task:1", job_id="job:2", facts=facts(), run_angr=run_angr  # type: ignore[arg-type]
        )
        assert planned.degraded is True
        assert planned.targets == ()
        assert planned.fallback_code == "model_unconfigured"

    asyncio.run(scenario())


def test_database_sink_persists_agent_run(persistence_database_url: str) -> None:
    async def scenario() -> None:
        suffix = uuid4().hex[:12]
        database = Database(DatabaseSettings(persistence_database_url))
        async with database.transaction() as repositories:
            await repositories.projects.add(project(f"project:{suffix}"))
            await repositories.artifacts.add(
                artifact(
                    f"artifact:{suffix}",
                    project_id=f"project:{suffix}",
                    current_version_id=f"artifact-version:{suffix}",
                )
            )
            await repositories.artifacts.add_version(
                artifact_version(
                    f"artifact-version:{suffix}", artifact_id=f"artifact:{suffix}"
                )
            )
            await repositories.tasks.create(
                task(
                    f"task:{suffix}",
                    project_id=f"project:{suffix}",
                    artifact_version_ids=[f"artifact-version:{suffix}"],
                    idempotency_key=f"task-key:{suffix}",
                )
            )
        sink = DatabaseAgentRunSink(database)
        run = cast(
            AgentRun,
            {
                "schema_version": "1.0.0",
                "id": f"agent-run:{suffix}",
                "task_id": f"task:{suffix}",
                "status": RunStatus.SUCCEEDED,
                "model": "planning/test",
                "prompt_hash": "sha256:" + "a" * 64,
                "input_refs": [],
                "decisions": [],
                "token_usage": {"input_tokens": 1, "output_tokens": 1},
                "failure": None,
                "created_at": TIMESTAMP,
                "updated_at": TIMESTAMP,
            },
        )
        try:
            await sink.add(run)
            async with database.transaction() as repositories:
                stored = await repositories.agent_runs.get(f"agent-run:{suffix}")
            assert stored["id"] == f"agent-run:{suffix}"
        finally:
            await database.dispose()

    asyncio.run(scenario())

