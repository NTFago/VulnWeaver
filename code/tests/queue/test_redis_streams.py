from __future__ import annotations

import asyncio
import copy
import json
import sys
from typing import cast

import pytest
from redis.asyncio import Redis
from vulnweaver_contracts import QueueEvent
from vulnweaver_queue import (
    MalformedQueueMessage,
    QueueConfigurationError,
    QueueMessageConflict,
    QueueSettings,
    QueueUnavailable,
    RedisStreamsClient,
)

from tests.persistence.factories import job, job_event, task_event

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


def test_publish_is_idempotent_and_consumer_group_requires_ack(
    redis_url: str, redis_namespace: str
) -> None:
    async def scenario() -> None:
        client = RedisStreamsClient(QueueSettings(redis_url, namespace=redis_namespace))
        raw = Redis.from_url(redis_url, decode_responses=True)
        try:
            event = job_event(job(), "event:t05-queue")
            first = await client.publish(event)
            repeated = await client.publish(event)

            assert repeated.message_id == first.message_id
            assert await raw.xlen(client.streams.jobs) == 1
            await client.ensure_group(client.streams.jobs, "workers")
            await client.ensure_group(client.streams.jobs, "workers")
            messages = await client.read_group(
                client.streams.jobs,
                "workers",
                "worker-1",
                block_milliseconds=10,
            )
            assert len(messages) == 1
            assert messages[0].event == event
            assert await client.acknowledge(
                client.streams.jobs, "workers", messages[0].message_id
            )
            assert not await client.acknowledge(
                client.streams.jobs, "workers", messages[0].message_id
            )
        finally:
            await raw.aclose()
            await client.close()

    asyncio.run(scenario())


def test_same_event_id_with_different_content_is_rejected(
    redis_url: str, redis_namespace: str
) -> None:
    async def scenario() -> None:
        client = RedisStreamsClient(QueueSettings(redis_url, namespace=redis_namespace))
        try:
            event = job_event(job(), "event:t05-conflict")
            await client.publish(event)
            conflicting = copy.deepcopy(event)
            conflicting["correlation_id"] = "task:different"
            with pytest.raises(QueueMessageConflict) as captured:
                await client.publish(conflicting)
            assert captured.value.details == {"event_id": "event:t05-conflict"}
        finally:
            await client.close()

    asyncio.run(scenario())


def test_retry_republishes_when_the_original_stream_entry_was_removed(
    redis_url: str, redis_namespace: str
) -> None:
    async def scenario() -> None:
        client = RedisStreamsClient(QueueSettings(redis_url, namespace=redis_namespace))
        raw = Redis.from_url(redis_url, decode_responses=True)
        try:
            event = job_event(job(), "event:t05-removed")
            first = await client.publish(event)
            assert await raw.xdel(client.streams.jobs, first.message_id) == 1
            repeated = await client.publish(event)
            assert repeated.message_id != first.message_id
            assert await raw.xlen(client.streams.jobs) == 1
        finally:
            await raw.aclose()
            await client.close()

    asyncio.run(scenario())


def test_status_events_use_the_events_stream(redis_url: str, redis_namespace: str) -> None:
    async def scenario() -> None:
        client = RedisStreamsClient(QueueSettings(redis_url, namespace=redis_namespace))
        try:
            published = await client.publish(task_event(identifier="event:t05-task"))
            assert published.stream == client.streams.events
            await client.healthcheck()
        finally:
            await client.close()

    asyncio.run(scenario())


def test_malformed_stream_entry_is_not_acknowledged(
    redis_url: str, redis_namespace: str
) -> None:
    async def scenario() -> None:
        raw = Redis.from_url(redis_url, decode_responses=True)
        client = RedisStreamsClient(
            QueueSettings(redis_url, namespace=redis_namespace), client=raw
        )
        try:
            await raw.xadd(client.streams.events, {"event": "not-json"})
            await client.ensure_group(client.streams.events, "api-events")
            with pytest.raises(MalformedQueueMessage):
                await client.read_group(
                    client.streams.events,
                    "api-events",
                    "api-1",
                    block_milliseconds=10,
                )
        finally:
            await client.close()

    asyncio.run(scenario())


def test_redundant_stream_fields_must_match_the_event_payload(
    redis_url: str, redis_namespace: str
) -> None:
    async def scenario() -> None:
        client = RedisStreamsClient(QueueSettings(redis_url, namespace=redis_namespace))
        raw = Redis.from_url(redis_url, decode_responses=True)
        try:
            event = job_event(job(), "event:t05-field-mismatch")
            await raw.xadd(
                client.streams.jobs,
                {
                    "event": json.dumps(event),
                    "event_id": "event:t05-tampered",
                    "event_type": event["event_type"],
                    "aggregate_id": event["aggregate_id"],
                    "sequence": str(event["sequence"]),
                    "correlation_id": event["correlation_id"],
                },
            )
            await client.ensure_group(client.streams.jobs, "workers")
            with pytest.raises(MalformedQueueMessage):
                await client.read_group(
                    client.streams.jobs,
                    "workers",
                    "worker-1",
                    block_milliseconds=10,
                )
        finally:
            await raw.aclose()
            await client.close()

    asyncio.run(scenario())


def test_stream_read_bounds_use_structured_configuration_errors(
    redis_url: str, redis_namespace: str
) -> None:
    async def scenario() -> None:
        client = RedisStreamsClient(QueueSettings(redis_url, namespace=redis_namespace))
        try:
            with pytest.raises(QueueConfigurationError):
                await client.read_group(
                    client.streams.jobs,
                    "workers",
                    "worker-1",
                    count=0,
                )
            with pytest.raises(QueueConfigurationError):
                await client.read_group(
                    client.streams.jobs,
                    "workers",
                    "worker-1",
                    block_milliseconds=60_001,
                )
        finally:
            await client.close()

    asyncio.run(scenario())


def test_invalid_event_and_unavailable_redis_are_structured(
    redis_namespace: str,
) -> None:
    async def scenario() -> None:
        invalid_client = RedisStreamsClient(
            QueueSettings("redis://127.0.0.1:6379/15", namespace=redis_namespace)
        )
        unavailable_client = RedisStreamsClient(
            QueueSettings(
                "redis://127.0.0.1:1/0",
                namespace=f"{redis_namespace}_down",
                socket_timeout_seconds=0.05,
            )
        )
        try:
            with pytest.raises(MalformedQueueMessage):
                await invalid_client.publish(
                    cast(QueueEvent, {"schema_version": "1.0.0"})
                )
            with pytest.raises(QueueUnavailable) as captured:
                await unavailable_client.publish(job_event(job(), "event:t05-down"))
            assert captured.value.retryable
            assert captured.value.details["operation"] == "publish"
        finally:
            await invalid_client.close()
            await unavailable_client.close()

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "settings",
    [
        {"url": "http://localhost:6379"},
        {"url": "redis://localhost:6379", "namespace": "unsafe:name"},
        {"url": "redis://localhost:6379", "socket_timeout_seconds": 0},
        {"url": "redis://localhost:6379", "deduplication_ttl_seconds": 1},
        {"url": "redis://localhost:6379", "stream_maxlen": 0},
    ],
)
def test_queue_configuration_has_safe_bounds(settings: dict[str, object]) -> None:
    with pytest.raises(QueueConfigurationError):
        QueueSettings(**settings)  # type: ignore[arg-type]
