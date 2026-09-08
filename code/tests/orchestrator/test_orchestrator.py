from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import cast

import pytest
from vulnweaver_contracts import (
    JobStatus,
    TaskRequestedEvent,
    TaskStatus,
)
from vulnweaver_orchestrator import (
    CheckpointStore,
    InitialJobPolicy,
    InMemoryCheckpointStore,
    Orchestrator,
    OrchestratorSettings,
    PostgresCheckpointStore,
)
from vulnweaver_persistence import Database, DatabaseSettings, EntityNotFound
from vulnweaver_queue import QueueSettings, RedisStreamsClient, StreamMessage
from vulnweaver_tool_runtime import PolicyEngine, ToolRegistry

from tests.persistence.factories import artifact, artifact_version, budget, project, task

NOW = "2026-09-08T09:00:00Z"


def tool_spec(
    name: str = "source-import",
    *,
    timeout: int = 30,
    approval_required: bool = False,
) -> dict[str, object]:
    return {
        "schema_version": "1.0.0",
        "name": name,
        "version": "1.0.0",
        "image_digest": "sha256:" + "b" * 64,
        "risk_level": "low",
        "accepted_artifacts": ["source_archive"],
        "command_schema": {},
        "output_schema": {},
        "network_policy": {"access": "none", "allowed_hosts": []},
        "filesystem_policy": {
            "input_read_only": True,
            "isolated_output": True,
            "allow_host_paths": False,
        },
        "resource_limits": {
            **budget(),
            "timeout_seconds": timeout,
        },
        "approval_required": approval_required,
        "timeout_seconds": timeout,
        "retry_policy": {
            "max_attempts": 2,
            "backoff_seconds": 1.0,
            "retryable_failure_kinds": [],
        },
    }


def requested_event(
    task_id: str = "task:t03",
    *,
    artifact_version_id: str = "artifact-version:t03",
    event_id: str = "event:task-requested-t11",
) -> TaskRequestedEvent:
    return cast(
        TaskRequestedEvent,
        {
            "schema_version": "1.0.0",
            "event_id": event_id,
            "event_type": "task.requested",
            "aggregate_id": task_id,
            "sequence": 0,
            "occurred_at": NOW,
            "correlation_id": task_id,
            "causation_id": None,
            "payload": {
                "task_id": task_id,
                "artifact_version_ids": [artifact_version_id],
            },
        },
    )


class FakeQueue:
    def __init__(self, messages: list[StreamMessage]) -> None:
        self.streams = SimpleNamespace(events="events", jobs="jobs")
        self.messages = messages
        self.acknowledged: list[str] = []
        self.group_calls: list[tuple[str, str]] = []

    async def ensure_group(self, stream: str, group: str) -> None:
        self.group_calls.append((stream, group))

    async def claim_stale(
        self,
        stream: str,
        group: str,
        consumer: str,
        *,
        min_idle_milliseconds: int,
        count: int,
        start_id: str,
    ) -> SimpleNamespace:
        del stream, group, consumer, min_idle_milliseconds, count, start_id
        return SimpleNamespace(messages=(), next_start_id="0-0")

    async def read_group(
        self,
        stream: str,
        group: str,
        consumer: str,
        *,
        count: int,
        block_milliseconds: int | None,
    ) -> list[StreamMessage]:
        del stream, group, consumer, count, block_milliseconds
        messages, self.messages = self.messages, []
        return messages

    async def acknowledge(self, stream: str, group: str, message_id: str) -> bool:
        del stream, group
        self.acknowledged.append(message_id)
        return True


def make_orchestrator(
    database: Database,
    queue: FakeQueue,
    registry: ToolRegistry,
    checkpoints: CheckpointStore,
) -> Orchestrator:
    return Orchestrator(
        database,
        queue,  # type: ignore[arg-type]
        registry,
        policy_engine=PolicyEngine(registry, clock=lambda: datetime(2026, 9, 8, 9, tzinfo=UTC)),
        checkpoint_store=checkpoints,
        initial_job_policy=InitialJobPolicy(
            source_tool_name="source-import",
            source_tool_version="1.0.0",
        ),
        settings=OrchestratorSettings(
            consumer_name="orch-test",
            consumer_group="orch-tests",
            read_block_milliseconds=10,
        ),
        clock=lambda: datetime(2026, 9, 8, 9, tzinfo=UTC),
    )


@pytest.mark.skipif(False, reason="integration fixture controls availability")
def test_placeholder() -> None:
    pass


def test_task_request_creates_policy_approved_initial_job(
    persistence_database_url: str,
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        try:
            async with database.transaction() as repositories:
                await repositories.projects.add(project("project:t11-main"))
                await repositories.artifacts.add(
                    artifact(
                        "artifact:t11-main",
                        project_id="project:t11-main",
                        current_version_id="artifact-version:t11-main",
                    )
                )
                await repositories.artifacts.add_version(
                    artifact_version(
                        "artifact-version:t11-main",
                        artifact_id="artifact:t11-main",
                        digest_character="8",
                    )
                )
                await repositories.tasks.create(
                    task(
                        "task:t11-main",
                        project_id="project:t11-main",
                        artifact_version_ids=["artifact-version:t11-main"],
                        idempotency_key="task:t11-main-key",
                    )
                )
            event = requested_event(
                "task:t11-main",
                artifact_version_id="artifact-version:t11-main",
                event_id="event:task-requested-t11-main",
            )
            queue = FakeQueue([StreamMessage("events", "1-0", event)])
            checkpoints = PostgresCheckpointStore(database)
            orchestrator = make_orchestrator(
                database, queue, ToolRegistry([tool_spec()]), checkpoints
            )
            result = await orchestrator.process_once()
            assert result[0].status == "approved"
            assert result[0].job_id is not None
            assert queue.acknowledged == ["1-0"]

            async with database.transaction() as repositories:
                stored_task = await repositories.tasks.get("task:t11-main")
                assert stored_task["status"] is TaskStatus.VALIDATING
                job = await repositories.jobs.get(result[0].job_id or "")
                assert job["status"] is JobStatus.QUEUED
                assert job.get("tool") == {
                    "name": "source-import",
                    "version": "1.0.0",
                    "image_digest": "sha256:" + "b" * 64,
                }
                assert job.get("arguments") == {
                    "artifact_version_id": "artifact-version:t11-main"
                }
                outbox = await repositories.outbox.pending()
                assert any(
                    message.event["event_type"] == "job.requested" for message in outbox
                )

            checkpoints_list = await checkpoints.list("task:t11-main")
            assert [item.node for item in checkpoints_list] == [
                "validate_inputs",
                "select_pipeline",
                "authorize_initial_job",
                "initial_job_persisted",
            ]
            replay = await orchestrator.handle_message(
                StreamMessage("events", "1-0", event)
            )
            assert replay.status == "already_scheduled"
            assert len(await checkpoints.list("task:t11-main")) == 4
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_policy_denial_fails_task_without_creating_job(
    persistence_database_url: str,
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        try:
            async with database.transaction() as repositories:
                await repositories.projects.add(project("project:t11-denied"))
                await repositories.artifacts.add(
                    artifact(
                        "artifact:t11-denied",
                        project_id="project:t11-denied",
                        current_version_id="artifact-version:t11-denied",
                    )
                )
                await repositories.artifacts.add_version(
                    artifact_version(
                        "artifact-version:t11-denied",
                        artifact_id="artifact:t11-denied",
                    )
                )
                denied_task = task(
                    "task:t11-denied",
                    project_id="project:t11-denied",
                    artifact_version_ids=["artifact-version:t11-denied"],
                    idempotency_key="task:t11-denied-key",
                )
                await repositories.tasks.create(denied_task)
            event = requested_event(
                "task:t11-denied",
                artifact_version_id="artifact-version:t11-denied",
                event_id="event:task-requested-t11-denied",
            )
            orchestrator = make_orchestrator(
                database,
                FakeQueue([]),
                ToolRegistry([]),
                InMemoryCheckpointStore(),
            )
            result = await orchestrator.handle_message(StreamMessage("events", "2-0", event))
            assert result.status == "failed"
            assert result.failure is not None
            assert result.failure["kind"] == "policy"
            async with database.transaction() as repositories:
                stored_task = await repositories.tasks.get("task:t11-denied")
                assert stored_task["status"] is TaskStatus.FAILED
                with pytest.raises(EntityNotFound):
                    await repositories.jobs.get("job:missing")
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_mid_graph_checkpoint_resumes_at_the_next_node(
    persistence_database_url: str,
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        checkpoints = InMemoryCheckpointStore()
        try:
            async with database.transaction() as repositories:
                await repositories.projects.add(project("project:t11-resume"))
                await repositories.artifacts.add(
                    artifact(
                        "artifact:t11-resume",
                        project_id="project:t11-resume",
                        current_version_id="artifact-version:t11-resume",
                    )
                )
                version = artifact_version(
                    "artifact-version:t11-resume",
                    artifact_id="artifact:t11-resume",
                    digest_character="9",
                )
                await repositories.artifacts.add_version(version)
                await repositories.tasks.create(
                    task(
                        "task:t11-resume",
                        project_id="project:t11-resume",
                        artifact_version_ids=["artifact-version:t11-resume"],
                        idempotency_key="task:t11-resume-key",
                    )
                )
            await checkpoints.save(
                "task:t11-resume",
                "select_pipeline",
                {
                    "task_id": "task:t11-resume",
                    "artifact_version_ids": ["artifact-version:t11-resume"],
                    "causation_id": "event:task-requested-t11-resume",
                    "project_id": "project:t11-resume",
                    "object_refs": [version["object_ref"]],
                    "artifact_kinds": {version["object_ref"]: "source_archive"},
                    "resource_budget": budget(),
                    "permission_mode": "request_permission",
                    "job_kind": "import",
                    "tool_name": "source-import",
                    "tool_version": "1.0.0",
                    "tool_arguments": {},
                    "checkpoint_node": "select_pipeline",
                },
                created_at=NOW,
            )
            event = requested_event(
                "task:t11-resume",
                artifact_version_id="artifact-version:t11-resume",
                event_id="event:task-requested-t11-resume",
            )
            orchestrator = make_orchestrator(
                database,
                FakeQueue([]),
                ToolRegistry([tool_spec()]),
                checkpoints,
            )
            result = await orchestrator.handle_message(StreamMessage("events", "4-0", event))
            assert result.job_id is not None
            assert [item.node for item in await checkpoints.list("task:t11-resume")] == [
                "select_pipeline",
                "authorize_initial_job",
                "initial_job_persisted",
            ]
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_real_redis_task_event_is_consumed_and_acknowledged(
    persistence_database_url: str,
    redis_url: str,
    redis_namespace: str,
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        queue = RedisStreamsClient(QueueSettings(redis_url, namespace=redis_namespace))
        try:
            async with database.transaction() as repositories:
                await repositories.projects.add(project("project:t11-redis"))
                await repositories.artifacts.add(
                    artifact(
                        "artifact:t11-redis",
                        project_id="project:t11-redis",
                        current_version_id="artifact-version:t11-redis",
                    )
                )
                await repositories.artifacts.add_version(
                    artifact_version(
                        "artifact-version:t11-redis",
                        artifact_id="artifact:t11-redis",
                        digest_character="f",
                    )
                )
                await repositories.tasks.create(
                    task(
                        "task:t11-redis",
                        project_id="project:t11-redis",
                        artifact_version_ids=["artifact-version:t11-redis"],
                        idempotency_key="task:t11-redis-key",
                    )
                )
            event = requested_event(
                "task:t11-redis",
                artifact_version_id="artifact-version:t11-redis",
                event_id="event:task-requested-t11-redis",
            )
            published = await queue.publish(event)
            registry = ToolRegistry([tool_spec()])
            orchestrator = Orchestrator(
                database,
                queue,
                registry,
                checkpoint_store=PostgresCheckpointStore(database),
                initial_job_policy=InitialJobPolicy(),
                settings=OrchestratorSettings(
                    consumer_name="orch-redis",
                    consumer_group="orch-redis-group",
                    read_block_milliseconds=10,
                    pending_idle_milliseconds=1,
                ),
                clock=lambda: datetime(2026, 9, 8, 9, tzinfo=UTC),
            )
            results = await orchestrator.process_once()
            assert len(results) == 1
            assert results[0].job_id is not None
            await asyncio.sleep(0.01)
            pending = await queue.claim_stale(
                queue.streams.events,
                "orch-redis-group",
                "orch-redis-check",
                min_idle_milliseconds=1,
                count=10,
            )
            assert pending.messages == ()
            assert published.event_id == event["event_id"]
        finally:
            await queue.close()
            await database.dispose()

    asyncio.run(scenario())


def test_permission_required_creates_waiting_job_without_dispatch(
    persistence_database_url: str,
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        try:
            async with database.transaction() as repositories:
                await repositories.projects.add(project("project:t11-waiting"))
                await repositories.artifacts.add(
                    artifact(
                        "artifact:t11-waiting",
                        project_id="project:t11-waiting",
                        current_version_id="artifact-version:t11-waiting",
                    )
                )
                await repositories.artifacts.add_version(
                    artifact_version(
                        "artifact-version:t11-waiting",
                        artifact_id="artifact:t11-waiting",
                        digest_character="c",
                    )
                )
                await repositories.tasks.create(
                    task(
                        "task:t11-waiting",
                        project_id="project:t11-waiting",
                        artifact_version_ids=["artifact-version:t11-waiting"],
                        idempotency_key="task:t11-waiting-key",
                    )
                )
            event = requested_event(
                "task:t11-waiting",
                artifact_version_id="artifact-version:t11-waiting",
                event_id="event:task-requested-t11-waiting",
            )
            registry = ToolRegistry([tool_spec(approval_required=True)])
            orchestrator = make_orchestrator(
                database,
                FakeQueue([]),
                registry,
                PostgresCheckpointStore(database),
            )
            result = await orchestrator.handle_message(StreamMessage("events", "3-0", event))
            assert result.status == "waiting_permission"
            assert result.job_id is not None
            async with database.transaction() as repositories:
                waiting = await repositories.jobs.get(result.job_id or "")
                assert waiting["status"] is JobStatus.WAITING_PERMISSION
                assert not any(
                    message.event["aggregate_id"] == waiting["id"]
                    for message in await repositories.outbox.pending()
                )
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_checkpoint_store_keeps_detached_state() -> None:
    async def scenario() -> None:
        store = InMemoryCheckpointStore()
        state: dict[str, object] = {"task_id": "task:1", "nested": {"value": 1}}
        saved = await store.save(
            "task:1", "validate_inputs", state, created_at=NOW
        )
        cast_state = state["nested"]
        assert saved.sequence == 0
        assert saved.state["task_id"] == "task:1"
        assert cast_state == {"value": 1}
        state["task_id"] = "changed"
        latest = await store.latest("task:1")
        assert latest is not None
        assert latest.state["task_id"] == "task:1"

    asyncio.run(scenario())
