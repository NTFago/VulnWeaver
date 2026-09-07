"""Outbox polling, publishing and durable delivery outcome recording."""

from __future__ import annotations

import asyncio
from contextlib import suppress
from dataclasses import dataclass
from datetime import timedelta

from vulnweaver_persistence import Database, PersistenceInvariantError
from vulnweaver_queue import EventPublisher, QueueError


@dataclass(frozen=True, slots=True)
class DispatcherSettings:
    batch_size: int = 100
    poll_interval_seconds: float = 0.5
    retry_base_seconds: float = 1.0
    retry_max_seconds: float = 300.0

    def __post_init__(self) -> None:
        if self.batch_size < 1 or self.batch_size > 1000:
            raise ValueError("dispatcher batch size must be between 1 and 1000")
        if self.poll_interval_seconds <= 0:
            raise ValueError("dispatcher poll interval must be positive")
        if self.retry_base_seconds < 0:
            raise ValueError("dispatcher retry base must not be negative")
        if self.retry_max_seconds < self.retry_base_seconds:
            raise ValueError("dispatcher retry maximum must cover the base delay")


@dataclass(frozen=True, slots=True)
class DispatchFailure:
    event_id: str
    code: str
    retryable: bool


@dataclass(frozen=True, slots=True)
class DispatchReport:
    fetched: int
    published: int
    failed: int
    dead_lettered: int
    failures: tuple[DispatchFailure, ...]


class OutboxDispatcher:
    def __init__(
        self,
        database: Database,
        publisher: EventPublisher,
        settings: DispatcherSettings | None = None,
    ) -> None:
        self._database = database
        self._publisher = publisher
        self._settings = settings or DispatcherSettings()

    async def dispatch_once(self) -> DispatchReport:
        published = 0
        failed = 0
        dead_lettered = 0
        failures: list[DispatchFailure] = []
        fetched = 0
        for _ in range(self._settings.batch_size):
            async with self._database.transaction() as repositories:
                messages = await repositories.outbox.claim_pending(limit=1)
                if not messages:
                    break
                fetched += 1
                message = messages[0]
                event_id = message.event["event_id"]
                try:
                    await self._publisher.publish(message.event)
                except QueueError as error:
                    failures.append(
                        DispatchFailure(
                            event_id=event_id,
                            code=error.code,
                            retryable=error.retryable,
                        )
                    )
                    if error.retryable:
                        retry_after = self._retry_delay(message.publish_attempts + 1)
                        updated = await repositories.outbox.mark_failed(
                            event_id,
                            error=error.as_dict(),
                            retry_after=retry_after,
                        )
                        failed += 1
                    else:
                        updated = await repositories.outbox.mark_dead_lettered(
                            event_id,
                            reason=error.as_dict(),
                        )
                        dead_lettered += 1
                    if not updated:
                        raise PersistenceInvariantError(
                            "claimed Outbox event could not record its failure",
                            details={"event_id": event_id},
                        ) from error
                    continue

                updated = await repositories.outbox.mark_published(event_id)
                if not updated:
                    raise PersistenceInvariantError(
                        "claimed Outbox event could not be marked published",
                        details={"event_id": event_id},
                    )
                published += 1

        return DispatchReport(
            fetched=fetched,
            published=published,
            failed=failed,
            dead_lettered=dead_lettered,
            failures=tuple(failures),
        )

    async def run(self, stop: asyncio.Event) -> None:
        while not stop.is_set():
            report = await self.dispatch_once()
            if report.fetched >= self._settings.batch_size:
                continue
            with suppress(TimeoutError):
                await asyncio.wait_for(
                    stop.wait(), timeout=self._settings.poll_interval_seconds
                )

    def _retry_delay(self, attempt: int) -> timedelta:
        exponent = min(attempt - 1, 30)
        seconds = min(
            self._settings.retry_max_seconds,
            self._settings.retry_base_seconds * (2**exponent),
        )
        return timedelta(seconds=seconds)
