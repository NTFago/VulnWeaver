from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import cast

import pytest
from vulnweaver_contracts import AgentRun, RunStatus
from vulnweaver_persistence import Database, DatabaseSettings, IdempotencyConflict

from tests.persistence.factories import artifact, artifact_version, project, task


def agent_run(model: str = "remote/planner") -> AgentRun:
    return cast(
        AgentRun,
        {
            "schema_version": "1.0.0",
            "id": "run:t11",
            "task_id": "task:t11-runs",
            "status": RunStatus.SUCCEEDED,
            "model": model,
            "prompt_hash": "sha256:" + "d" * 64,
            "input_refs": ["cas://sha256/" + "d" * 64],
            "decisions": [
                {
                    "sequence": 1,
                    "decision": "model_attempt",
                    "reason": "selected planning tier",
                    "created_at": "2026-09-08T09:00:00Z",
                }
            ],
            "token_usage": {"input_tokens": 12, "output_tokens": 5},
            "duration_ms": 15,
            "result_refs": ["cas://sha256/" + "e" * 64],
            "failure": None,
            "created_at": "2026-09-08T09:00:00Z",
            "updated_at": "2026-09-08T09:00:00Z",
        },
    )


def test_agent_runs_and_checkpoints_are_durable_and_idempotent(
    persistence_database_url: str,
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        try:
            async with database.transaction() as repositories:
                await repositories.projects.add(project("project:t11-runs"))
                await repositories.artifacts.add(
                    artifact(
                        "artifact:t11-runs",
                        project_id="project:t11-runs",
                        current_version_id="artifact-version:t11-runs",
                    )
                )
                await repositories.artifacts.add_version(
                    artifact_version(
                        "artifact-version:t11-runs",
                        artifact_id="artifact:t11-runs",
                        digest_character="d",
                    )
                )
                await repositories.tasks.create(
                    task(
                        "task:t11-runs",
                        project_id="project:t11-runs",
                        artifact_version_ids=["artifact-version:t11-runs"],
                        idempotency_key="task:t11-runs-key",
                    )
                )

            run = agent_run()
            async with database.transaction() as repositories:
                created = await repositories.agent_runs.add(run)
                replay = await repositories.agent_runs.add(run)
                assert created.created
                assert not replay.created
                assert (await repositories.agent_runs.get(run["id"])) == run
                assert await repositories.agent_runs.list_for_task(run["task_id"]) == [run]
                first = await repositories.checkpoints.append(
                    run["task_id"],
                    "validate_inputs",
                    {"task_id": run["task_id"], "phase": "validated"},
                    created_at=datetime(2026, 9, 8, 9, tzinfo=UTC),
                )
                second = await repositories.checkpoints.append(
                    run["task_id"],
                    "select_pipeline",
                    {"task_id": run["task_id"], "phase": "selected"},
                    created_at=datetime(2026, 9, 8, 9, 1, tzinfo=UTC),
                )
                assert (first.sequence, second.sequence) == (0, 1)
                latest = await repositories.checkpoints.latest(run["task_id"])
                assert latest is not None
                assert latest.node == "select_pipeline"
                assert [
                    item.node
                    for item in await repositories.checkpoints.list_for_task(run["task_id"])
                ] == ["validate_inputs", "select_pipeline"]

            with pytest.raises(IdempotencyConflict):
                async with database.transaction() as repositories:
                    await repositories.agent_runs.add(agent_run("other/model"))
        finally:
            await database.dispose()

    asyncio.run(scenario())
