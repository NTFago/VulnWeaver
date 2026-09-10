"""Orchestrator process entry point."""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys
from pathlib import Path
from types import FrameType

from vulnweaver_orchestrator import (
    InitialJobPolicy,
    Orchestrator,
    OrchestratorSettings,
    PostgresCheckpointStore,
)
from vulnweaver_persistence import Database, DatabaseSettings
from vulnweaver_queue import QueueSettings, RedisStreamsClient
from vulnweaver_tool_runtime import ToolSpecLoader

LOGGER = logging.getLogger("vulnweaver.orchestrator")


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
    registry = ToolSpecLoader.load_directory(Path(_required_environment("TOOL_SPEC_DIRECTORY")))
    orchestrator = Orchestrator(
        database,
        queue,
        registry,
        checkpoint_store=PostgresCheckpointStore(database),
        initial_job_policy=InitialJobPolicy(
            source_tool_name=os.environ.get("SOURCE_IMPORT_TOOL_NAME", "source-import"),
            source_tool_version=os.environ.get("SOURCE_IMPORT_TOOL_VERSION", "1.0.0"),
            binary_tool_name=os.environ.get("BINARY_IMPORT_TOOL_NAME", "binary-import"),
            binary_tool_version=os.environ.get("BINARY_IMPORT_TOOL_VERSION", "1.0.0"),
        ),
        settings=OrchestratorSettings(
            consumer_name=os.environ.get("ORCHESTRATOR_CONSUMER_NAME", "orchestrator-1"),
            consumer_group=os.environ.get("ORCHESTRATOR_CONSUMER_GROUP", "orchestrators"),
            read_block_milliseconds=_environment_int(
                "ORCHESTRATOR_READ_BLOCK_MILLISECONDS", 1000
            ),
            pending_idle_milliseconds=_environment_int(
                "ORCHESTRATOR_PENDING_IDLE_MILLISECONDS", 30_000
            ),
            retry_base_seconds=_environment_float("ORCHESTRATOR_RETRY_BASE_SECONDS", 1.0),
            retry_max_seconds=_environment_float("ORCHESTRATOR_RETRY_MAX_SECONDS", 30.0),
        ),
    )
    stop = asyncio.Event()
    _install_signal_handlers(stop)
    try:
        await database.healthcheck()
        await queue.healthcheck()
        LOGGER.info("orchestrator_started")
        async for results in orchestrator.run(stop):
            for result in results:
                LOGGER.info(
                    "orchestration_result task_id=%s job_id=%s status=%s acknowledged=%s "
                    "failure_code=%s failure_details=%s",
                    result.task_id,
                    result.job_id,
                    result.status,
                    result.acknowledged,
                    result.failure["code"] if result.failure is not None else None,
                    result.failure["details"] if result.failure is not None else None,
                )
    finally:
        await queue.close()
        await database.dispose()
        LOGGER.info("orchestrator_stopped")


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

    def fallback_handler(_signum: int, _frame: FrameType | None) -> None:
        loop.call_soon_threadsafe(stop.set)

    for signal_name in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(signal_name, stop.set)
        except NotImplementedError:
            signal.signal(signal_name, fallback_handler)
