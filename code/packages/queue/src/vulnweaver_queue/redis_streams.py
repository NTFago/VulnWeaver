"""Versioned QueueEvent transport over Redis Streams."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Protocol, cast

from redis.asyncio import Redis
from redis.exceptions import RedisError, ResponseError
from vulnweaver_contracts import ContractValidationError, QueueEvent, validate_contract

from vulnweaver_queue.errors import (
    MalformedQueueMessage,
    QueueConfigurationError,
    QueueMessageConflict,
    QueueUnavailable,
)

_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_EVENT_ID_CONFLICT = "EVENT_ID_CONFLICT"
_PUBLISH_SCRIPT = """
local existing_id = redis.call('HGET', KEYS[2], 'message_id')
if existing_id then
    local existing_fingerprint = redis.call('HGET', KEYS[2], 'fingerprint')
    if existing_fingerprint ~= ARGV[1] then
        return redis.error_reply('EVENT_ID_CONFLICT')
    end
    local existing_entry = redis.call(
        'XRANGE', KEYS[1], existing_id, existing_id, 'COUNT', 1
    )
    if #existing_entry > 0 then
        return existing_id
    end
end

local message_id
if ARGV[3] == '' then
    message_id = redis.call('XADD', KEYS[1], '*', unpack(ARGV, 4))
else
    message_id = redis.call(
        'XADD', KEYS[1], 'MAXLEN', '~', ARGV[3], '*', unpack(ARGV, 4)
    )
end
redis.call(
    'HSET', KEYS[2], 'message_id', message_id, 'fingerprint', ARGV[1]
)
redis.call('EXPIRE', KEYS[2], ARGV[2])
return message_id
"""


@dataclass(frozen=True, slots=True)
class QueueSettings:
    url: str
    namespace: str = "vulnweaver"
    socket_timeout_seconds: float = 5.0
    deduplication_ttl_seconds: int = 7 * 24 * 60 * 60
    stream_maxlen: int | None = None

    def __post_init__(self) -> None:
        if not self.url.startswith(("redis://", "rediss://")):
            raise QueueConfigurationError("queue URL must use redis:// or rediss://")
        if _SAFE_NAME.fullmatch(self.namespace) is None:
            raise QueueConfigurationError("queue namespace contains unsafe characters")
        if self.socket_timeout_seconds <= 0:
            raise QueueConfigurationError("queue socket timeout must be positive")
        if self.deduplication_ttl_seconds < 60:
            raise QueueConfigurationError("queue deduplication TTL must be at least 60 seconds")
        if self.stream_maxlen is not None and self.stream_maxlen < 1:
            raise QueueConfigurationError("queue stream_maxlen must be positive")


@dataclass(frozen=True, slots=True)
class StreamNames:
    jobs: str
    events: str


@dataclass(frozen=True, slots=True)
class PublishedMessage:
    stream: str
    message_id: str
    event_id: str


@dataclass(frozen=True, slots=True)
class StreamMessage:
    stream: str
    message_id: str
    event: QueueEvent


class EventPublisher(Protocol):
    async def publish(self, event: QueueEvent) -> PublishedMessage: ...


class RedisStreamsClient:
    def __init__(self, settings: QueueSettings, *, client: Redis | None = None) -> None:
        self._settings = settings
        key_tag = f"{{{settings.namespace}}}"
        self.streams = StreamNames(
            jobs=f"{key_tag}:jobs",
            events=f"{key_tag}:events",
        )
        self._client = client or Redis.from_url(
            settings.url,
            decode_responses=True,
            socket_connect_timeout=settings.socket_timeout_seconds,
            socket_timeout=settings.socket_timeout_seconds,
            health_check_interval=30,
        )

    async def publish(self, event: QueueEvent) -> PublishedMessage:
        try:
            validate_contract("QueueEvent", event)
        except ContractValidationError as error:
            raise MalformedQueueMessage(
                "queue event failed contract validation",
                details={"definition": error.definition},
            ) from error

        encoded = _encode_event(event)
        fingerprint = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        stream = self._stream_for(event["event_type"])
        deduplication_key = self._deduplication_key(event["event_id"])
        fields = [
            "event",
            encoded,
            "event_id",
            event["event_id"],
            "event_type",
            event["event_type"],
            "aggregate_id",
            event["aggregate_id"],
            "sequence",
            str(event["sequence"]),
            "correlation_id",
            event["correlation_id"],
        ]
        try:
            response = await self._client.eval(
                _PUBLISH_SCRIPT,
                2,
                stream,
                deduplication_key,
                fingerprint,
                self._settings.deduplication_ttl_seconds,
                self._settings.stream_maxlen or "",
                *fields,
            )
        except ResponseError as error:
            if _EVENT_ID_CONFLICT in str(error):
                raise QueueMessageConflict(
                    "event identifier was already published with different content",
                    details={"event_id": event["event_id"]},
                ) from error
            raise _unavailable("publish", error) from error
        except RedisError as error:
            raise _unavailable("publish", error) from error
        return PublishedMessage(
            stream=stream,
            message_id=_string(response),
            event_id=event["event_id"],
        )

    async def ensure_group(
        self, stream: str, group: str, *, start_id: str = "0-0"
    ) -> None:
        self._ensure_owned_stream(stream)
        _validate_consumer_name(group, "group")
        try:
            await self._client.xgroup_create(
                name=stream,
                groupname=group,
                id=start_id,
                mkstream=True,
            )
        except ResponseError as error:
            if "BUSYGROUP" not in str(error):
                raise _unavailable("create_consumer_group", error) from error
        except RedisError as error:
            raise _unavailable("create_consumer_group", error) from error

    async def read_group(
        self,
        stream: str,
        group: str,
        consumer: str,
        *,
        count: int = 10,
        block_milliseconds: int = 1000,
    ) -> list[StreamMessage]:
        self._ensure_owned_stream(stream)
        _validate_consumer_name(group, "group")
        _validate_consumer_name(consumer, "consumer")
        if count < 1 or count > 1000:
            raise ValueError("stream read count must be between 1 and 1000")
        if block_milliseconds < 0 or block_milliseconds > 60_000:
            raise ValueError("stream block duration must be between 0 and 60000 ms")
        try:
            response = await self._client.xreadgroup(
                groupname=group,
                consumername=consumer,
                streams={stream: ">"},
                count=count,
                block=block_milliseconds,
                noack=False,
            )
        except RedisError as error:
            raise _unavailable("read_group", error) from error
        return _decode_stream_response(response)

    async def acknowledge(
        self, stream: str, group: str, message_id: str
    ) -> bool:
        self._ensure_owned_stream(stream)
        _validate_consumer_name(group, "group")
        try:
            acknowledged = await self._client.xack(stream, group, message_id)
        except RedisError as error:
            raise _unavailable("acknowledge", error) from error
        return int(acknowledged) == 1

    async def healthcheck(self) -> None:
        try:
            await self._client.ping()
        except RedisError as error:
            raise _unavailable("healthcheck", error) from error

    async def close(self) -> None:
        await self._client.aclose()

    def _stream_for(self, event_type: str) -> str:
        if event_type == "job.requested":
            return self.streams.jobs
        return self.streams.events

    def _deduplication_key(self, event_id: str) -> str:
        event_hash = hashlib.sha256(event_id.encode("utf-8")).hexdigest()
        return f"{{{self._settings.namespace}}}:published:{event_hash}"

    def _ensure_owned_stream(self, stream: str) -> None:
        if stream not in (self.streams.jobs, self.streams.events):
            raise QueueConfigurationError("stream is outside the configured namespace")


def _encode_event(event: QueueEvent) -> str:
    return json.dumps(event, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _decode_stream_response(response: object) -> list[StreamMessage]:
    messages: list[StreamMessage] = []
    try:
        streams = cast(list[tuple[str, list[tuple[str, dict[str, str]]]]], response)
        for stream, entries in streams:
            for message_id, fields in entries:
                encoded = fields["event"]
                payload = json.loads(encoded)
                if not isinstance(payload, dict):
                    raise TypeError("event payload is not an object")
                validate_contract("QueueEvent", payload)
                messages.append(
                    StreamMessage(
                        stream=stream,
                        message_id=message_id,
                        event=cast(QueueEvent, payload),
                    )
                )
    except (ContractValidationError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise MalformedQueueMessage("Redis Stream entry contains an invalid event") from error
    return messages


def _validate_consumer_name(value: str, field: str) -> None:
    if _SAFE_NAME.fullmatch(value) is None:
        raise QueueConfigurationError(f"queue {field} contains unsafe characters")


def _unavailable(operation: str, error: RedisError) -> QueueUnavailable:
    return QueueUnavailable(
        "Redis operation failed",
        details={"operation": operation, "error_type": type(error).__name__},
    )


def _string(value: object) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8")
    return str(value)
