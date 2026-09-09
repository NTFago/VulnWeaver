"""Source analysis Worker process entry point."""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys
from types import FrameType

from vulnweaver_artifact_store import LocalContentAddressedStore
from vulnweaver_binary_analysis import BinaryImportExecutor
from vulnweaver_model_gateway import (
    ModelEndpoint,
    ModelGateway,
    ModelGatewaySettings,
    ModelRoute,
    ModelTier,
)
from vulnweaver_orchestrator import (
    IndependentModelReviewer,
    ReviewJobExecutor,
    ReviewJobScheduler,
    TaskAggregateSettlementHook,
)
from vulnweaver_pair import SourcePairImporter
from vulnweaver_persistence import Database, DatabaseSettings
from vulnweaver_queue import QueueSettings, RedisStreamsClient
from vulnweaver_source_analysis import (
    AnalysisJobExecutor,
    SourceImportExecutor,
    StaticAnalysisExecutor,
    StaticAnalysisScheduler,
)
from vulnweaver_tool_runtime import ToolSpecLoader
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
    tool_registry = ToolSpecLoader.load_directory(
        os.environ.get("TOOL_SPEC_DIRECTORY", "/etc/vulnweaver/tool-specs")
    )
    static_specs = {
        spec["name"]: spec
        for spec in tool_registry.snapshot()
        if spec["name"] in {"semgrep", "cppcheck"}
    }
    scheduler = StaticAnalysisScheduler(database, static_specs)
    review_scheduler = ReviewJobScheduler(database)
    review_executor, model_gateway = _review_executor(database, store)
    pair_importer = SourcePairImporter(database)
    source_executor = SourceImportExecutor(
        database,
        store,
        scratch_root=os.environ.get("SOURCE_SCRATCH_ROOT", "/tmp"),
        static_scheduler=scheduler,
        pair_importer=pair_importer,
    )
    binary_executor = BinaryImportExecutor.configured(
        database,
        store,
        scratch_root=os.environ.get("BINARY_SCRATCH_ROOT", "/tmp"),
        die_executable=os.environ.get("DIE_EXECUTABLE", "diec"),
        objdump_executable=os.environ.get("OBJDUMP_EXECUTABLE", "objdump"),
        ghidra_executable=os.environ.get("GHIDRA_HEADLESS_EXECUTABLE") or None,
        ghidra_script_directory=os.environ.get("GHIDRA_SCRIPT_DIRECTORY", "/opt/vulnweaver/ghidra"),
        angr_enabled=_environment_bool("ANGR_ENABLED", False),
        upx_executable=os.environ.get("UPX_EXECUTABLE", "upx"),
    )
    executor = AnalysisJobExecutor(
        source_executor,
        StaticAnalysisExecutor(
            database,
            store,
            scratch_root=os.environ.get("SOURCE_SCRATCH_ROOT", "/tmp"),
        ),
        review_executor,
        binary_executor,
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
            pending_idle_milliseconds=_environment_int("WORKER_PENDING_IDLE_MILLISECONDS", 30_000),
            lease_seconds=_environment_int("WORKER_LEASE_SECONDS", 120),
            heartbeat_interval_seconds=_environment_int("WORKER_HEARTBEAT_INTERVAL_SECONDS", 30),
            shutdown_grace_seconds=float(os.environ.get("WORKER_SHUTDOWN_GRACE_SECONDS", "30")),
        ),
        settlement_hook=TaskAggregateSettlementHook(review_scheduler),
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
        if model_gateway is not None:
            await model_gateway.close()
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


def _environment_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise RuntimeError(f"{name} must be a boolean")


def _review_executor(
    database: Database, store: LocalContentAddressedStore
) -> tuple[ReviewJobExecutor, ModelGateway | None]:
    base_url = os.environ.get("REVIEW_MODEL_BASE_URL", "").strip()
    model = os.environ.get("REVIEW_MODEL_NAME", "").strip()
    if not base_url and not model:
        return ReviewJobExecutor(None), None
    if not base_url or not model:
        raise RuntimeError(
            "REVIEW_MODEL_BASE_URL and REVIEW_MODEL_NAME must be configured together"
        )
    endpoint = ModelEndpoint(
        name="review-model",
        base_url=base_url,
        models={ModelTier.REVIEW: model},
        api_key=os.environ.get("REVIEW_MODEL_API_KEY") or None,
        timeout_seconds=float(os.environ.get("REVIEW_MODEL_TIMEOUT_SECONDS", "60")),
        max_attempts=_environment_int("REVIEW_MODEL_MAX_ATTEMPTS", 2),
    )
    gateway = ModelGateway(
        ModelGatewaySettings(
            routes={ModelTier.REVIEW: ModelRoute(primary=endpoint)},
            max_repair_attempts=_environment_int("REVIEW_MODEL_REPAIR_ATTEMPTS", 1),
            min_request_interval_seconds=float(
                os.environ.get("REVIEW_MODEL_MIN_INTERVAL_SECONDS", "0")
            ),
        )
    )
    reviewer = IndependentModelReviewer(database, gateway, store)
    return ReviewJobExecutor(reviewer), gateway


def _install_signal_handlers(stop: asyncio.Event) -> None:
    loop = asyncio.get_running_loop()

    def fallback_handler(_signum: int, _frame: FrameType | None) -> None:
        loop.call_soon_threadsafe(stop.set)

    for signal_name in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(signal_name, stop.set)
        except NotImplementedError:
            signal.signal(signal_name, fallback_handler)
