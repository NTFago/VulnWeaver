"""Start the isolated Sandbox Runner with code-owned tool profiles."""

# pyright: reportUnusedFunction=false, reportDeprecated=false

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from typing import cast

import uvicorn
from vulnweaver_artifact_store import LocalContentAddressedStore
from vulnweaver_binary_analysis import binary_command_profile, binary_tool_spec
from vulnweaver_contracts import ResourceBudget
from vulnweaver_domain import ResolvedDeploymentConfig, resolve_deployment_config
from vulnweaver_fuzzing import afl_casr_command_profile, afl_casr_tool_spec
from vulnweaver_persistence import Database, DatabaseSettings
from vulnweaver_proof import proof_command_profile, proof_tool_spec
from vulnweaver_sandbox_runner import (
    DockerCliRuntime,
    SandboxCommandProfile,
    SandboxRunner,
    create_sandbox_app,
)
from vulnweaver_tool_runtime import ToolRegistry, ToolSpecLoader

LOGGER = logging.getLogger(__name__)


class SettingsReader:
    """Read the installation settings row, ignoring database outages.

    The runner keeps working with its last-resolved configuration when the
    database is unreachable; sandbox execution must never block on the
    control-plane database being down.
    """

    def __init__(self, database: Database | None) -> None:
        self._database = database
        self._fingerprint: str | None = None
        self._lock = asyncio.Lock()

    async def resolve(self) -> tuple[ResolvedDeploymentConfig | None, bool]:
        """Return (config, changed) where config is None without a database."""

        if self._database is None:
            return None, False
        try:
            async with self._database.transaction() as repositories:
                row = await repositories.product_settings.get_row()
        except Exception as error:  # noqa: BLE001 - degrade to last known config
            LOGGER.warning(
                "settings_read_failed",
                extra={"error": str(error)[:200]},
            )
            return None, False
        fingerprint = hashlib.sha256(
            json.dumps(row, sort_keys=True, default=str).encode()
        ).hexdigest()
        async with self._lock:
            changed = fingerprint != self._fingerprint
            self._fingerprint = fingerprint
        values = row["values"]
        config = resolve_deployment_config(
            cast(Mapping[str, object], values) if isinstance(values, dict) else {},
            os.environ,
        )
        return config, changed


@dataclass(frozen=True, slots=True)
class _RunnerState:
    registry: ToolRegistry
    profiles: tuple[SandboxCommandProfile, ...]


class ReconfigurableRunner:
    """Rebuild tool specs/profiles when installation settings change."""

    def __init__(self) -> None:
        self._state = _build_runner_state(None)
        self._lock = asyncio.Lock()

    @property
    def state(self) -> _RunnerState:
        return self._state

    async def refresh(self, config: ResolvedDeploymentConfig) -> None:
        async with self._lock:
            self._state = _build_runner_state(config)

    def runner(self, store: LocalContentAddressedStore, sandbox_root: str) -> SandboxRunner:
        state = self._state
        return SandboxRunner(
            store,
            state.registry,
            list(state.profiles),
            runtime=DockerCliRuntime(
                root=sandbox_root,
                docker_host_root=os.environ.get("DOCKER_HOST_SANDBOX_ROOT") or None,
            ),
            root=sandbox_root,
        )


def build_app():
    database = _connect_settings_database()
    reconfigurable = ReconfigurableRunner()
    reader = SettingsReader(database)
    store = LocalContentAddressedStore(
        os.environ.get("ARTIFACT_STORE_ROOT", "/var/lib/vulnweaver/artifacts")
    )
    sandbox_root = os.environ.get("SANDBOX_ROOT", "/var/lib/vulnweaver/sandbox")
    token = os.environ.get("SANDBOX_RUNNER_TOKEN", "").strip() or None

    async def _runner_source() -> SandboxRunner:
        config, changed = await reader.resolve()
        if config is not None and changed:
            await reconfigurable.refresh(config)
            LOGGER.info("sandbox_runner_reconfigured")
        return reconfigurable.runner(store, sandbox_root)

    app = create_sandbox_app(_runner_source, bearer_token=token)
    if database is not None:

        @app.on_event("shutdown")
        async def _dispose_database() -> None:  # pragma: no cover - lifecycle glue
            await database.dispose()

    return app


def _connect_settings_database() -> Database | None:
    url = os.environ.get("DATABASE_URL", "").strip()
    if not url:
        return None
    try:
        return Database(DatabaseSettings(url=url, pool_size=1, max_overflow=0))
    except ValueError as error:
        LOGGER.warning("settings_database_disabled", extra={"error": str(error)[:200]})
        return None


def _build_runner_state(config: ResolvedDeploymentConfig | None) -> _RunnerState:
    registry = ToolSpecLoader.load_directory(
        os.environ.get("TOOL_SPEC_DIRECTORY", "/etc/vulnweaver/tool-specs")
    )
    profiles: list[SandboxCommandProfile] = []
    fuzz_ref = os.environ.get("AFL_CASR_IMAGE_REF", "vulnweaver-afl-casr:fixed")
    fuzz_digest = _digest(config, "afl_casr") or _resolve_local_image_digest(fuzz_ref)
    proof_ref = os.environ.get("PROOF_IMAGE_REF", "vulnweaver-proof:fixed")
    proof_digest = _digest(config, "proof_tool") or _resolve_local_image_digest(proof_ref)
    binary_ref = os.environ.get("BINARY_TOOLS_IMAGE_REF", "vulnweaver-binary-tools:fixed")
    binary_digest = _digest(config, "binary_tools") or _resolve_local_image_digest(binary_ref)
    if binary_digest:
        registry.register(
            binary_tool_spec(binary_digest, _binary_resource_budget(config))
        )
        profiles.append(binary_command_profile(binary_ref, binary_digest))
    if proof_digest:
        registry.register(proof_tool_spec(proof_digest, _resource_budget(config)))
        profiles.append(proof_command_profile(proof_ref, proof_digest))
    if fuzz_digest:
        registry.register(afl_casr_tool_spec(fuzz_digest, _fuzz_resource_budget(config)))
        profiles.append(afl_casr_command_profile(fuzz_ref, fuzz_digest))
    return _RunnerState(registry, tuple(profiles))


def _digest(config: ResolvedDeploymentConfig | None, name: str) -> str:
    if config is None:
        return ""
    value = getattr(config.digests, name, None)
    return value or ""


def _budget_value(config: ResolvedDeploymentConfig | None, tool: str, field: str) -> int | None:
    if config is None:
        return None
    budget = config.budgets.get(tool)
    return getattr(budget, field, None) if budget is not None else None


def _resource_budget(config: ResolvedDeploymentConfig | None) -> ResourceBudget:
    return {
        "max_model_tokens": 0,
        "cpu_millis": _budget_value(config, "proof", "cpu_millis") or 1000,
        "memory_bytes": _budget_value(config, "proof", "memory_bytes")
        or 256 * 1024 * 1024,
        "disk_bytes": _budget_value(config, "proof", "disk_bytes") or 256 * 1024 * 1024,
        "max_tool_concurrency": 1,
        "max_dynamic_runs": 1,
        "timeout_seconds": _budget_value(config, "proof", "timeout_seconds") or 120,
    }


def _fuzz_resource_budget(config: ResolvedDeploymentConfig | None) -> ResourceBudget:
    return {
        "max_model_tokens": 0,
        "cpu_millis": _budget_value(config, "afl", "cpu_millis") or 4000,
        "memory_bytes": _budget_value(config, "afl", "memory_bytes")
        or 1024 * 1024 * 1024,
        "disk_bytes": _budget_value(config, "afl", "disk_bytes") or 512 * 1024 * 1024,
        "max_tool_concurrency": 1,
        "max_dynamic_runs": 1,
        "timeout_seconds": _budget_value(config, "afl", "timeout_seconds") or 300,
    }


def _binary_resource_budget(config: ResolvedDeploymentConfig | None) -> ResourceBudget:
    return {
        "max_model_tokens": 0,
        "cpu_millis": _budget_value(config, "binary", "cpu_millis") or 4000,
        "memory_bytes": _budget_value(config, "binary", "memory_bytes")
        or 3 * 1024 * 1024 * 1024,
        "disk_bytes": _budget_value(config, "binary", "disk_bytes") or 1024 * 1024 * 1024,
        "max_tool_concurrency": 1,
        "max_dynamic_runs": 0,
        "timeout_seconds": _budget_value(config, "binary", "timeout_seconds") or 600,
    }


def _resolve_local_image_digest(image_ref: str) -> str:
    """Resolve a locally built fixed image without weakening digest pinning."""
    try:
        result = subprocess.run(
            ["docker", "image", "inspect", "--format", "{{.Id}}", image_ref],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    digest = result.stdout.strip()
    return digest if digest.startswith("sha256:") else ""



app = build_app()


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))
