from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest
from redis.asyncio import Redis
from sqlalchemy import select, update
from vulnweaver_dispatcher import DispatcherSettings, OutboxDispatcher
from vulnweaver_persistence import Database, DatabaseSettings
from vulnweaver_persistence.models import outbox_events
from vulnweaver_queue import (
    PublishedMessage,
    QueueMessageConflict,
    QueueSettings,
    QueueUnavailable,
    RedisStreamsClient,
)

from tests.persistence.factories import (
    artifact,
    artifact_version,
    job,
    job_event,
    project,
    task,
)


def test_dispatcher_publishes_and_crash_window_retry_does_not_duplicate_stream_entry(
    persistence_database_url: str,
    redis_url: str,
    redis_namespace: str,
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        queue = RedisStreamsClient(QueueSettings(redis_url, namespace=redis_namespace))
        raw = Redis.from_url(redis_url, decode_responses=True)
        event_id = "event:t05-dispatch"
        try:
            await _seed_outbox(database, "dispatch", event_id)
            dispatcher = OutboxDispatcher(database, queue)
            first = await dispatcher.dispatch_once()
            assert first.published == 1
            assert first.failed == 0
            assert await raw.xlen(queue.streams.jobs) == 1

            async with database.engine.begin() as connection:
                await connection.execute(
                    update(outbox_events)
                    .where(outbox_events.c.id == event_id)
                    .values(published_at=None)
                )
            replay = await dispatcher.dispatch_once()
            assert replay.published == 1
            assert await raw.xlen(queue.streams.jobs) == 1

            rows = await raw.xrange(queue.streams.jobs)
            assert rows[0][1]["event_id"] == event_id
            async with database.transaction() as repositories:
                pending_ids = {
                    message.event["event_id"]
                    for message in await repositories.outbox.pending()
                }
            assert event_id not in pending_ids
        finally:
            await raw.aclose()
            await queue.close()
            await database.dispose()

    asyncio.run(scenario())


def test_dispatcher_records_retryable_and_terminal_failures(
    persistence_database_url: str,
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        try:
            await _seed_outbox(database, "retry", "event:t05-retry")
            before_retry = datetime.now(UTC)
            retry_dispatcher = OutboxDispatcher(
                database,
                _FailingPublisher(QueueUnavailable("redis is unavailable")),
                DispatcherSettings(retry_base_seconds=2, retry_max_seconds=10),
            )
            retry_report = await retry_dispatcher.dispatch_once()
            after_retry = datetime.now(UTC)
            assert retry_report.failed == 1
            assert retry_report.dead_lettered == 0
            retry_row = await _outbox_row(database, "event:t05-retry")
            assert retry_row["publish_attempts"] == 1
            # PostgreSQL may run in a VM whose wall clock differs slightly from the host.
            assert before_retry + timedelta(seconds=1) <= retry_row["available_at"]
            assert retry_row["available_at"] <= after_retry + timedelta(seconds=3)
            assert retry_row["last_error"]["code"] == "queue_unavailable"

            await _seed_outbox(database, "dead", "event:t05-dead")
            dead_dispatcher = OutboxDispatcher(
                database,
                _FailingPublisher(QueueMessageConflict("event ID conflict")),
            )
            dead_report = await dead_dispatcher.dispatch_once()
            assert dead_report.dead_lettered == 1
            dead_row = await _outbox_row(database, "event:t05-dead")
            assert dead_row["dead_lettered_at"] is not None
            assert dead_row["dead_letter_reason"]["code"] == "queue_message_conflict"
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_concurrent_dispatchers_do_not_lock_an_entire_batch(
    persistence_database_url: str,
    redis_url: str,
    redis_namespace: str,
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        first_queue = RedisStreamsClient(
            QueueSettings(redis_url, namespace=redis_namespace)
        )
        second_queue = RedisStreamsClient(
            QueueSettings(redis_url, namespace=redis_namespace)
        )
        blocking = _BlockingPublisher(first_queue)
        first = OutboxDispatcher(database, blocking, DispatcherSettings(batch_size=2))
        second = OutboxDispatcher(
            database, second_queue, DispatcherSettings(batch_size=2)
        )
        first_task: asyncio.Task[object] | None = None
        try:
            await _seed_outbox(database, "concurrent-a", "event:t05-concurrent-a")
            await _seed_outbox(database, "concurrent-b", "event:t05-concurrent-b")

            first_task = asyncio.create_task(first.dispatch_once())
            await asyncio.wait_for(blocking.started.wait(), timeout=2)
            second_report = await asyncio.wait_for(second.dispatch_once(), timeout=2)
            blocking.release.set()
            first_report = await asyncio.wait_for(first_task, timeout=2)

            assert second_report.published == 1
            assert first_report.published == 1
        finally:
            blocking.release.set()
            if first_task is not None and not first_task.done():
                await first_task
            await first_queue.close()
            await second_queue.close()
            await database.dispose()

    asyncio.run(scenario())


def test_dispatcher_loop_stops_without_claiming_more_work(
    persistence_database_url: str,
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        stop = asyncio.Event()
        stop.set()
        try:
            dispatcher = OutboxDispatcher(database, _FailingPublisher(None))
            await dispatcher.run(stop)
        finally:
            await database.dispose()

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "settings",
    [
        {"batch_size": 0},
        {"batch_size": 1001},
        {"poll_interval_seconds": 0},
        {"retry_base_seconds": -1},
        {"retry_base_seconds": 2, "retry_max_seconds": 1},
    ],
)
def test_dispatcher_configuration_has_safe_bounds(settings: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        DispatcherSettings(**settings)  # type: ignore[arg-type]


class _FailingPublisher:
    def __init__(self, error: Exception | None) -> None:
        self._error = error

    async def publish(self, event: object) -> PublishedMessage:
        if self._error is not None:
            raise self._error
        return PublishedMessage("unused", "0-0", str(event))


class _BlockingPublisher:
    def __init__(self, delegate: RedisStreamsClient) -> None:
        self._delegate = delegate
        self.started = asyncio.Event()
        self.release = asyncio.Event()

    async def publish(self, event: object) -> PublishedMessage:
        self.started.set()
        await self.release.wait()
        return await self._delegate.publish(event)  # type: ignore[arg-type]


async def _seed_outbox(database: Database, suffix: str, event_id: str) -> None:
    project_id = f"project:t05-{suffix}"
    artifact_id = f"artifact:t05-{suffix}"
    version_id = f"artifact-version:t05-{suffix}"
    task_id = f"task:t05-{suffix}"
    job_id = f"job:t05-{suffix}"
    queued_job = job(
        job_id,
        task_id=task_id,
        idempotency_key=f"job:t05-{suffix}-key",
    )
    async with database.transaction() as repositories:
        await repositories.projects.add(project(project_id))
        await repositories.artifacts.add(
            artifact(
                artifact_id,
                project_id=project_id,
                current_version_id=version_id,
            )
        )
        await repositories.artifacts.add_version(
            artifact_version(version_id, artifact_id=artifact_id)
        )
        await repositories.tasks.create(
            task(
                task_id,
                project_id=project_id,
                artifact_version_ids=[version_id],
                idempotency_key=f"task:t05-{suffix}-key",
            )
        )
        await repositories.jobs.enqueue_with_outbox(
            queued_job, job_event(queued_job, event_id)
        )


async def _outbox_row(database: Database, event_id: str) -> object:
    async with database.engine.connect() as connection:
        return (
            await connection.execute(
                select(outbox_events).where(outbox_events.c.id == event_id)
            )
        ).mappings().one()
