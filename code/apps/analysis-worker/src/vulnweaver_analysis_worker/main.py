"""Source analysis Worker process entry point."""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys
from types import FrameType
from typing import Any

from vulnweaver_artifact_store import ArtifactRegistrationService, LocalContentAddressedStore
from vulnweaver_binary_analysis import BinaryImportExecutor
from vulnweaver_contracts import CrashRecord, ResourceBudget, ToolIdentity
from vulnweaver_fuzzing import (
    AFL_CASR_TOOL_NAME,
    AFL_CASR_TOOL_VERSION,
    CASR_TOOL_NAME,
    CASR_TOOL_VERSION,
    FuzzExecutionService,
    FuzzJobExecutor,
    afl_casr_tool_spec,
)
from vulnweaver_model_gateway import (
    ModelEndpoint,
    ModelGateway,
    ModelGatewaySettings,
    ModelRoute,
    ModelTier,
)
from vulnweaver_orchestrator import (
    CriticalLogicConfirmer,
    DatabaseAgentRunSink,
    IndependentModelReviewer,
    ReversePlanningAgent,
    ReviewJobExecutor,
    ReviewJobScheduler,
    SemanticAuditJobExecutor,
    SemanticAuditor,
    SemanticAuditScheduler,
    TaskAggregateSettlementHook,
    persist_crash_evidence,
)
from vulnweaver_pair import BinaryPairImporter, SourcePairImporter
from vulnweaver_persistence import Database, DatabaseSettings
from vulnweaver_proof import (
    AutoExploitScheduler,
    ExploitScriptGenerator,
    ProofExecutionService,
    ProofJobExecutor,
    SandboxRunnerClient,
)
from vulnweaver_queue import QueueSettings, RedisStreamsClient
from vulnweaver_reporting import ReportJobExecutor
from vulnweaver_source_analysis import (
    AnalysisJobExecutor,
    SourceImportExecutor,
    StaticAnalysisExecutor,
    StaticAnalysisScheduler,
)
from vulnweaver_tool_runtime import ToolRegistry, ToolSpecLoader
from vulnweaver_worker import ReliableWorker, WorkerSettings

from vulnweaver_analysis_worker.readable_pseudocode import ModelReadablePseudocodeHook

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
    audit_scheduler = SemanticAuditScheduler(database)
    exploit_scheduler = _auto_exploit_scheduler(database)
    review_executor, audit_executor, model_gateway = await _model_executors(database, store)
    report_executor = ReportJobExecutor(
        database,
        ArtifactRegistrationService(store, database),
        tool=ToolIdentity(
            name="vulnweaver-report",
            version=os.environ.get("REPORT_TOOL_VERSION", "1.0.0"),
            image_digest=None,
        ),
    )
    proof_executor = _proof_executor(database, store, model_gateway)
    fuzz_executor = await _fuzz_executor(database, store, tool_registry)
    pair_importer = SourcePairImporter(database)
    source_executor = SourceImportExecutor(
        database,
        store,
        scratch_root=os.environ.get("SOURCE_SCRATCH_ROOT", "/tmp"),
        static_scheduler=scheduler,
        pair_importer=pair_importer,
    )
    binary_sandbox, binary_digest = await _binary_sandbox()
    binary_planning_hook = (
        _ReversePlanningHook(
            ReversePlanningAgent(model_gateway, database, sink=DatabaseAgentRunSink(database))
        )
        if model_gateway is not None
        else None
    )
    critical_logic_hook = (
        CriticalLogicConfirmer(
            model_gateway, sink=DatabaseAgentRunSink(database)
        )
        if model_gateway is not None
        else None
    )
    binary_executor = BinaryImportExecutor.configured(
        database,
        store,
        scratch_root=os.environ.get("BINARY_SCRATCH_ROOT", "/tmp"),
        die_executable=os.environ.get("DIE_EXECUTABLE", "diec"),
        objdump_executable=os.environ.get("OBJDUMP_EXECUTABLE", "objdump"),
        ghidra_executable=os.environ.get("GHIDRA_HEADLESS_EXECUTABLE") or None,
        ghidra_script_directory=os.environ.get("GHIDRA_SCRIPT_DIRECTORY", "/opt/vulnweaver/ghidra"),
        # Symbolic execution is dynamic analysis and may only run through the
        # independent Sandbox Runner; never enable the worker-local adapter.
        angr_enabled=(
            _environment_bool("ANGR_ENABLED", False) and binary_sandbox is not None
        ),
        upx_executable=os.environ.get("UPX_EXECUTABLE", "upx"),
        pair_importer=BinaryPairImporter(database),
        sandbox=binary_sandbox,
        sandbox_image_digest=binary_digest,
        planning_hook=binary_planning_hook,
        critical_logic_hook=critical_logic_hook,
        readable_pseudocode_hook=(
            ModelReadablePseudocodeHook(model_gateway) if model_gateway is not None else None
        ),
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
        proof=proof_executor,
        report=report_executor,
        semantic_audit=audit_executor,
        fuzz=fuzz_executor,
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
        settlement_hook=TaskAggregateSettlementHook(
            review_scheduler, audit_scheduler, exploit_scheduler
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
        if model_gateway is not None:
            await model_gateway.close()
        await queue.close()
        await database.dispose()
        LOGGER.info("analysis_worker_stopped")


class _ReversePlanningHook:
    """Bridge the orchestrator planning agent to the binary executor hook."""

    def __init__(self, agent: ReversePlanningAgent) -> None:
        self._agent = agent

    async def plan(
        self, job: Any, facts: Any, run_angr: Any
    ) -> tuple[int, ...]:
        planned = await self._agent.plan(
            task_id=str(job["task_id"]),
            job_id=str(job["id"]),
            facts=facts,
            run_angr=run_angr,
        )
        return planned.targets


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


async def _model_executors(
    database: Database, store: LocalContentAddressedStore
) -> tuple[ReviewJobExecutor, SemanticAuditJobExecutor | None, ModelGateway | None]:
    async with database.transaction() as repositories:
        product_settings = await repositories.product_settings.get()
    base_url = str(product_settings.get("review_model_base_url", "")).strip()
    model = str(product_settings.get("review_model_name", "")).strip()
    if not base_url and not model:
        return ReviewJobExecutor(None), None, None
    if not base_url or not model:
        raise RuntimeError(
            "REVIEW_MODEL_BASE_URL and REVIEW_MODEL_NAME must be configured together"
        )
    stored_api_key = product_settings.get("review_model_api_key")
    if stored_api_key is not None and not isinstance(stored_api_key, str):
        raise RuntimeError("stored review model API key is invalid")
    endpoint = ModelEndpoint(
        name="review-model",
        base_url=base_url,
        # The configured product model serves both the REVIEW and AUDIT tiers
        # until dedicated audit-model settings exist.
        models={ModelTier.REVIEW: model, ModelTier.AUDIT: model},
        api_key=stored_api_key,
        timeout_seconds=_setting_float(product_settings, "review_model_timeout_seconds", 60),
        max_attempts=_setting_int(product_settings, "review_model_max_attempts", 2),
    )
    gateway = ModelGateway(
        ModelGatewaySettings(
            routes={
                ModelTier.REVIEW: ModelRoute(primary=endpoint),
                ModelTier.AUDIT: ModelRoute(primary=endpoint),
            },
            proxy_url=os.environ.get("REVIEW_MODEL_PROXY_URL") or None,
            max_repair_attempts=_setting_int(
                product_settings, "review_model_repair_attempts", 1
            ),
            min_request_interval_seconds=_setting_float(
                product_settings, "review_model_min_interval_seconds", 0
            ),
        )
    )
    reviewer = IndependentModelReviewer(database, gateway, store)
    auditor = SemanticAuditor(database, gateway, store)
    return (
        ReviewJobExecutor(reviewer),
        SemanticAuditJobExecutor(database, auditor),
        gateway,
    )


def _setting_int(settings: dict[str, object], name: str, default: int) -> int:
    value = settings.get(name, default)
    if not isinstance(value, (int, float, str)):
        raise RuntimeError(f"stored {name} is not numeric")
    return int(value)


def _setting_float(settings: dict[str, object], name: str, default: float) -> float:
    value = settings.get(name, default)
    if not isinstance(value, (int, float, str)):
        raise RuntimeError(f"stored {name} is not numeric")
    return float(value)


def _proof_executor(
    database: Database,
    store: LocalContentAddressedStore,
    model_gateway: ModelGateway | None,
) -> ProofJobExecutor | None:
    runner_url = os.environ.get("SANDBOX_RUNNER_URL", "").strip()
    if not runner_url:
        return None
    client = _sandbox_client(
        runner_url, float(os.environ.get("SANDBOX_RUNNER_TIMEOUT_SECONDS", "60"))
    )
    service = ProofExecutionService(
        client,
        tool_name=os.environ.get("PROOF_TOOL_NAME", "proof-tool"),
        tool_version=os.environ.get("PROOF_TOOL_VERSION", "1.0.0"),
    )
    generator = (
        ExploitScriptGenerator(database, model_gateway, store)
        if model_gateway is not None
        else None
    )
    return ProofJobExecutor(database, service, script_generator=generator)


def _auto_exploit_scheduler(database: Database) -> AutoExploitScheduler | None:
    image_digest = os.environ.get("PROOF_TOOL_IMAGE_DIGEST", "").strip()
    if not image_digest:
        # Without a pinned proof image the automatic exploit pipeline stays off.
        return None
    return AutoExploitScheduler(database, image_digest=image_digest)


def _sandbox_client(runner_url: str, timeout: float) -> SandboxRunnerClient:
    """Build a Runner client that authenticates whenever the deployment pins a token."""

    return SandboxRunnerClient(
        runner_url,
        timeout_seconds=timeout,
        bearer_token=os.environ.get("SANDBOX_RUNNER_TOKEN", "").strip() or None,
    )


def _fuzz_resource_budget() -> ResourceBudget:
    return ResourceBudget(
        max_model_tokens=0,
        cpu_millis=int(os.environ.get("AFL_CPU_MILLIS", "4000")),
        memory_bytes=int(os.environ.get("AFL_MEMORY_BYTES", str(1024 * 1024 * 1024))),
        disk_bytes=int(os.environ.get("AFL_DISK_BYTES", str(512 * 1024 * 1024))),
        max_tool_concurrency=1,
        max_dynamic_runs=1,
        timeout_seconds=int(os.environ.get("AFL_TIMEOUT_SECONDS", "300")),
    )


async def _fuzz_executor(
    database: Database, store: LocalContentAddressedStore, tool_registry: ToolRegistry
) -> FuzzJobExecutor | None:
    """Assemble the fuzz executor from the digest the Runner actually enforces.

    The pinned digest is read from the Runner's registered-tool endpoint when the
    deployment did not supply one, so no caller-supplied digest or command reaches
    the sandbox.
    """

    runner_url = os.environ.get("SANDBOX_RUNNER_URL", "").strip()
    if not runner_url:
        return None
    client = _sandbox_client(
        runner_url, float(os.environ.get("FUZZ_RUNNER_TIMEOUT_SECONDS", "600"))
    )
    try:
        spec = tool_registry.get(AFL_CASR_TOOL_NAME, AFL_CASR_TOOL_VERSION)
    except KeyError:
        digest = await client.tool_digest(AFL_CASR_TOOL_NAME, AFL_CASR_TOOL_VERSION)
        if digest is None:
            # No pinned fuzz image on either side: leave the executor unconfigured
            # rather than let an unpinned request reach the Runner.
            return None
        spec = afl_casr_tool_spec(digest, _fuzz_resource_budget())
        tool_registry.register(spec)
    return FuzzJobExecutor(
        FuzzExecutionService(
            store,
            tool_registry,
            client,
            fuzz_tool=ToolIdentity(
                name=spec["name"], version=spec["version"], image_digest=spec["image_digest"]
            ),
            crash_tool=ToolIdentity(
                name=CASR_TOOL_NAME, version=CASR_TOOL_VERSION, image_digest=spec["image_digest"]
            ),
        ),
        crash_sink=_CrashEvidenceSink(database),
    )


class _CrashEvidenceSink:
    def __init__(self, database: Database) -> None:
        self._database = database

    async def persist(
        self, *, finding_id: str, crashes: tuple[CrashRecord, ...], created_by: str
    ) -> tuple[str, ...]:
        async with self._database.transaction() as repositories:
            return await persist_crash_evidence(
                repositories, finding_id=finding_id, crashes=crashes, created_by=created_by
            )


async def _binary_sandbox() -> tuple[SandboxRunnerClient | None, str | None]:
    runner_url = os.environ.get("SANDBOX_RUNNER_URL", "").strip()
    if not runner_url:
        return None, None
    client = _sandbox_client(
        runner_url, float(os.environ.get("SANDBOX_RUNNER_TIMEOUT_SECONDS", "600"))
    )
    digest = os.environ.get("BINARY_TOOLS_IMAGE_DIGEST", "").strip() or None
    if digest is None:
        digest = await client.tool_digest("binary-facts", "1.0.0")
    return client, digest


def _install_signal_handlers(stop: asyncio.Event) -> None:
    loop = asyncio.get_running_loop()

    def fallback_handler(_signum: int, _frame: FrameType | None) -> None:
        loop.call_soon_threadsafe(stop.set)

    for signal_name in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(signal_name, stop.set)
        except NotImplementedError:
            signal.signal(signal_name, fallback_handler)
