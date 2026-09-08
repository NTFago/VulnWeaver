"""Source analysis Worker process entry point."""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys
from types import FrameType

from vulnweaver_artifact_store import LocalContentAddressedStore
from vulnweaver_persistence import Database, DatabaseSettings
from vulnweaver_queue import QueueSettings, RedisStreamsClient
from vulnweaver_source_analysis import SourceImportExecutor
from vulnweaver_worker import ReliableWorker, WorkerSettings

LOGGER = logging.getLogger("vulnweaver.analysis-worker")


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(_run())


async def _run() -> None:
    database = Database(DatabaseSettings(_required_environment("DATABASE_URL")))
    queue = RedisStreamsClient(
        QueueSettings(
            _required_environment("REDIS_URL"),
            namespace=os.environ.get("REDIS_STREAM_NAMESPACE", "vulnweaver"),
        )
    )
    store = LocalContentAddressedStore(_required_environment("ARTIFACT_STORE_ROOT"))
    executor = SourceImportExecutor(
        database,
        store,
        scratch_root=os.environ.get("SOURCE_SCRATCH_ROOT", "/tmp"),
    )
    worker = ReliableWorker(
        database,
        queue,
        executor,
        WorkerSettings(
            consumer_name=os.environ.get("WORKER_CONSUMER_NAME", "analysis-worker-1"),
            consumer_group=os.environ.get("WORKER_CONSUMER_GROUP", "analysis-workers"),
            concurrency=_environment_int("WORKER_CONCURRENCY", 1),
            read_block_milliseconds=_environment_int("WORKER_READ_BLOCK_MILLISECONDS", 1000),
            pending_idle_milliseconds=_environment_int(
                "WORKER_PENDING_IDLE_MILLISECONDS", 30_000
            ),
            lease_seconds=_environment_int("WORKER_LEASE_SECONDS", 120),
            heartbeat_interval_seconds=_environment_int(
                "WORKER_HEARTBEAT_INTERVAL_SECONDS", 30
            ),
            shutdown_grace_seconds=float(
                os.environ.get("WORKER_SHUTDOWN_GRACE_SECONDS", "30")
            ),
        ),
    )
    stop = asyncio.Event()
    _install_signal_handlers(stop)
    try:
        await database.healthcheck()
        await queue.healthcheck()
        store.healthcheck()
        LOGGER.info("analysis_worker_started")
        await worker.run(stop)
    finally:
        await queue.close()
        await database.dispose()
        LOGGER.info("analysis_worker_stopped")


def _required_environment(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


def _environment_int(name: str, default: int) -> int:
    value = os.environ.get(name)
    return default if value is None else int(value)


def _install_signal_handlers(stop: asyncio.Event) -> None:
    loop = asyncio.get_running_loop()

    def fallback_handler(_signum: int, _frame: FrameType | None) -> None:
        loop.call_soon_threadsafe(stop.set)

    for signal_name in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(signal_name, stop.set)
        except NotImplementedError:
            signal.signal(signal_name, fallback_handler)
