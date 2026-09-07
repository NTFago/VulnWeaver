"""Dispatcher process entry point."""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys

from vulnweaver_persistence import Database, DatabaseSettings
from vulnweaver_queue import QueueSettings, RedisStreamsClient

from vulnweaver_dispatcher.dispatcher import DispatcherSettings, OutboxDispatcher

LOGGER = logging.getLogger("vulnweaver.dispatcher")


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(_run())


async def _run() -> None:
    database_url = _required_environment("DATABASE_URL")
    redis_url = _required_environment("REDIS_URL")
    database = Database(DatabaseSettings(database_url))
    queue = RedisStreamsClient(
        QueueSettings(
            redis_url,
            namespace=os.environ.get("REDIS_STREAM_NAMESPACE", "vulnweaver"),
        )
    )
    dispatcher = OutboxDispatcher(
        database,
        queue,
        DispatcherSettings(
            batch_size=_environment_int("DISPATCHER_BATCH_SIZE", 100),
            poll_interval_seconds=_environment_float(
                "DISPATCHER_POLL_INTERVAL_SECONDS", 0.5
            ),
            retry_base_seconds=_environment_float(
                "DISPATCHER_RETRY_BASE_SECONDS", 1.0
            ),
            retry_max_seconds=_environment_float(
                "DISPATCHER_RETRY_MAX_SECONDS", 300.0
            ),
        ),
    )
    stop = asyncio.Event()
    _install_signal_handlers(stop)
    try:
        await database.healthcheck()
        await queue.healthcheck()
        LOGGER.info("dispatcher_started")
        await dispatcher.run(stop)
    finally:
        await queue.close()
        await database.dispose()
        LOGGER.info("dispatcher_stopped")


def _required_environment(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


def _environment_int(name: str, default: int) -> int:
    value = os.environ.get(name)
    return default if value is None else int(value)


def _environment_float(name: str, default: float) -> float:
    value = os.environ.get(name)
    return default if value is None else float(value)


def _install_signal_handlers(stop: asyncio.Event) -> None:
    loop = asyncio.get_running_loop()
    for signal_name in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(signal_name, stop.set)
        except NotImplementedError:
            signal.signal(signal_name, lambda *_args: loop.call_soon_threadsafe(stop.set))
