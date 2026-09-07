"""Versioned QueueEvent transport over Redis Streams."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol, cast

from redis.asyncio import Redis
from redis.exceptions import RedisError, ResponseError
from vulnweaver_contracts import (
    ContractValidationError,
    QueueEvent,
    StructuredFailure,
    validate_contract,
)

from vulnweaver_queue.errors import (
    MalformedQueueMessage,
    QueueConfigurationError,
    QueueMessageConflict,
    QueueUnavailable,
)

_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_EVENT_ID_CONFLICT = "EVENT_ID_CONFLICT"
_DEAD_LETTER_CONFLICT = "DEAD_LETTER_CONFLICT"
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
_DEAD_LETTER_SCRIPT = """
local existing_id = redis.call('HGET', KEYS[2], 'message_id')
if existing_id then
    local existing_fingerprint = redis.call('HGET', KEYS[2], 'fingerprint')
    if existing_fingerprint ~= ARGV[1] then
        return redis.error_reply('DEAD_LETTER_CONFLICT')
    end
    local existing_entry = redis.call(
        'XRANGE', KEYS[1], existing_id, existing_id, 'COUNT', 1
    )
    if #existing_entry > 0 then
        redis.call('XACK', KEYS[3], ARGV[4], ARGV[5])
        return existing_id
    end
end

local message_id
if ARGV[3] == '' then
    message_id = redis.call('XADD', KEYS[1], '*', unpack(ARGV, 6))
else
    message_id = redis.call(
        'XADD', KEYS[1], 'MAXLEN', '~', ARGV[3], '*', unpack(ARGV, 6)
    )
end
redis.call(
    'HSET', KEYS[2], 'message_id', message_id, 'fingerprint', ARGV[1]
)
redis.call('EXPIRE', KEYS[2], ARGV[2])
redis.call('XACK', KEYS[3], ARGV[4], ARGV[5])
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
    dead_letters: str


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


@dataclass(frozen=True, slots=True)
class StaleClaimBatch:
    next_start_id: str
    messages: tuple[StreamMessage, ...]


@dataclass(frozen=True, slots=True)
class DeadLetteredMessage:
    stream: str
    message_id: str
    original_message_id: str


class EventPublisher(Protocol):
    async def publish(self, event: QueueEvent) -> PublishedMessage: ...


class RedisStreamsClient:
    def __init__(self, settings: QueueSettings, *, client: Redis | None = None) -> None:
        self._settings = settings
        key_tag = f"{{{settings.namespace}}}"
        self.streams = StreamNames(
            jobs=f"{key_tag}:jobs",
            events=f"{key_tag}:events",
            dead_letters=f"{key_tag}:dead-letters",
        )
        self._client = client or Redis.from_url(  # pyright: ignore[reportUnknownMemberType]
            settings.url,
            decode_responses=True,
            socket_connect_timeout=settings.socket_timeout_seconds,
            socket_timeout=settings.socket_timeout_seconds,
            health_check_interval=30,
        )

    async def publish(self, event: QueueEvent) -> PublishedMessage:
        _validate_queue_contract("QueueEvent", event, "queue event")

        encoded = _encode_event(event)
        fingerprint = _text_fingerprint(encoded)
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

    async def ensure_group(self, stream: str, group: str, *, start_id: str = "0-0") -> None:
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
        block_milliseconds: int | None = 1000,
    ) -> list[StreamMessage]:
        self._ensure_owned_stream(stream)
        _validate_consumer_name(group, "group")
        _validate_consumer_name(consumer, "consumer")
        if count < 1 or count > 1000:
            raise QueueConfigurationError("stream read count must be between 1 and 1000")
        if block_milliseconds is not None and (
            block_milliseconds < 1 or block_milliseconds > 60_000
        ):
            raise QueueConfigurationError(
                "stream block duration must be between 1 and 60000 ms or omitted"
            )
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

    async def acknowledge(self, stream: str, group: str, message_id: str) -> bool:
        self._ensure_owned_stream(stream)
        _validate_consumer_name(group, "group")
        try:
            acknowledged = await self._client.xack(stream, group, message_id)
        except RedisError as error:
            raise _unavailable("acknowledge", error) from error
        return int(acknowledged) == 1

    async def dead_letter(
        self,
        stream: str,
        group: str,
        message: StreamMessage,
        *,
        failure: StructuredFailure,
        attempt: int,
    ) -> DeadLetteredMessage:
        """Atomically preserve a terminal failure and ACK its pending entry."""

        self._ensure_owned_stream(stream)
        if stream == self.streams.dead_letters or message.stream != stream:
            raise QueueConfigurationError("dead-letter source must match a configured work stream")
        _validate_consumer_name(group, "group")
        if attempt < 1:
            raise QueueConfigurationError("dead-letter attempt must be positive")
        _validate_queue_contract("StructuredFailure", failure, "dead-letter failure")

        encoded_event = _encode_event(message.event)
        encoded_failure = _stable_json(failure)
        fingerprint = _text_fingerprint(
            _stable_json(
                {
                    "stream": stream,
                    "message_id": message.message_id,
                    "event": message.event,
                    "failure": failure,
                    "attempt": attempt,
                }
            )
        )
        deduplication_key = self._dead_letter_deduplication_key(stream, message.message_id)
        fields = [
            "event",
            encoded_event,
            "original_stream",
            stream,
            "original_message_id",
            message.message_id,
            "failure",
            encoded_failure,
            "attempt",
            str(attempt),
        ]
        try:
            response = await self._client.eval(
                _DEAD_LETTER_SCRIPT,
                3,
                self.streams.dead_letters,
                deduplication_key,
                stream,
                fingerprint,
                self._settings.deduplication_ttl_seconds,
                self._settings.stream_maxlen or "",
                group,
                message.message_id,
                *fields,
            )
        except ResponseError as error:
            if _DEAD_LETTER_CONFLICT in str(error):
                raise QueueMessageConflict(
                    "pending entry was already dead-lettered with different content",
                    details={
                        "stream": stream,
                        "message_id": message.message_id,
                    },
                ) from error
            raise _unavailable("dead_letter", error) from error
        except RedisError as error:
            raise _unavailable("dead_letter", error) from error
        return DeadLetteredMessage(
            stream=self.streams.dead_letters,
            message_id=_string(response),
            original_message_id=message.message_id,
        )

    async def claim_stale(
        self,
        stream: str,
        group: str,
        consumer: str,
        *,
        min_idle_milliseconds: int,
        count: int = 10,
        start_id: str = "0-0",
    ) -> StaleClaimBatch:
        """Transfer idle pending entries to a live consumer using XAUTOCLAIM."""

        self._ensure_owned_stream(stream)
        _validate_consumer_name(group, "group")
        _validate_consumer_name(consumer, "consumer")
        if min_idle_milliseconds < 1 or min_idle_milliseconds > 86_400_000:
            raise QueueConfigurationError(
                "minimum pending idle duration must be between 1 ms and 24 hours"
            )
        if count < 1 or count > 1000:
            raise QueueConfigurationError("stale claim count must be between 1 and 1000")
        try:
            response = await self._client.xautoclaim(
                name=stream,
                groupname=group,
                consumername=consumer,
                min_idle_time=min_idle_milliseconds,
                start_id=start_id,
                count=count,
                justid=False,
            )
        except RedisError as error:
            raise _unavailable("claim_stale", error) from error
        return _decode_stale_claim(stream, response)

    async def healthcheck(self) -> None:
        try:
            await self._client.ping()  # pyright: ignore[reportUnknownMemberType]
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

    def _dead_letter_deduplication_key(self, stream: str, message_id: str) -> str:
        identity = f"{stream}\0{message_id}"
        message_hash = hashlib.sha256(identity.encode("utf-8")).hexdigest()
        return f"{{{self._settings.namespace}}}:dead-lettered:{message_hash}"

    def _ensure_owned_stream(self, stream: str) -> None:
        if stream not in (
            self.streams.jobs,
            self.streams.events,
            self.streams.dead_letters,
        ):
            raise QueueConfigurationError("stream is outside the configured namespace")


def _encode_event(event: QueueEvent) -> str:
    return _stable_json(event)


def _stable_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _text_fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _validate_queue_contract(
    definition: str, value: Mapping[str, object], description: str
) -> None:
    try:
        validate_contract(definition, value)
    except ContractValidationError as error:
        raise MalformedQueueMessage(
            f"{description} failed contract validation",
            details={"definition": error.definition},
        ) from error


def _decode_stream_response(response: object) -> list[StreamMessage]:
    messages: list[StreamMessage] = []
    try:
        streams = cast(list[tuple[str, list[tuple[str, dict[str, str]]]]], response)
        for stream, entries in streams:
            for message_id, fields in entries:
                encoded = fields["event"]
                decoded: object = json.loads(encoded)
                if not isinstance(decoded, dict):
                    raise TypeError("event payload is not an object")
                payload = cast(dict[str, object], decoded)
                validate_contract("QueueEvent", payload)
                for field in (
                    "event_id",
                    "event_type",
                    "aggregate_id",
                    "sequence",
                    "correlation_id",
                ):
                    if fields[field] != str(payload[field]):
                        raise ValueError(f"stream field {field} does not match payload")
                messages.append(
                    StreamMessage(
                        stream=stream,
                        message_id=message_id,
                        event=cast(QueueEvent, payload),
                    )
                )
    except (
        ContractValidationError,
        KeyError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
    ) as error:
        raise MalformedQueueMessage("Redis Stream entry contains an invalid event") from error
    return messages


def _decode_stale_claim(stream: str, response: object) -> StaleClaimBatch:
    try:
        values = cast(list[object], response)
        if len(values) < 2:
            raise ValueError("XAUTOCLAIM response is incomplete")
        next_start_id = _string(values[0])
        entries = cast(list[tuple[str, dict[str, str]]], values[1])
        messages = _decode_stream_response([(stream, entries)])
    except (TypeError, ValueError) as error:
        raise MalformedQueueMessage("Redis XAUTOCLAIM response is invalid") from error
    return StaleClaimBatch(next_start_id, tuple(messages))


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
