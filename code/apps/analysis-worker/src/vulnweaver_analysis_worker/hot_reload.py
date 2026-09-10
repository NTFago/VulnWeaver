"""Rebuild config-dependent worker components when installation settings change.

The worker resolves its model gateway, sandbox-backed executors and dispatch
schedulers from the installation settings row (managed via the web settings
page) merged over the process environment. Reads happen lazily before each job
execution and settlement; a change fingerprint avoids rebuilding when nothing
changed, and database outages degrade to the last-resolved assembly instead of
blocking job processing.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import cast

from vulnweaver_contracts import Job, WorkerResult
from vulnweaver_persistence import Database, Repositories

LOGGER = logging.getLogger("vulnweaver.analysis-worker.hot-reload")

@dataclass(frozen=True, slots=True)
class SettingsSnapshot:
    values: dict[str, object]
    fingerprint: str


async def read_settings_snapshot(database: Database) -> SettingsSnapshot | None:
    """Read the installation row; None means the database is unavailable."""

    try:
        async with database.transaction() as repositories:
            row = await repositories.product_settings.get_row()
    except Exception as error:  # noqa: BLE001 - degrade to the last assembly
        LOGGER.warning("settings_read_failed", extra={"error": str(error)[:200]})
        return None
    values = row["values"]
    resolved: dict[str, object] = (
        dict(cast(Mapping[str, object], values)) if isinstance(values, dict) else {}
    )
    fingerprint = hashlib.sha256(
        json.dumps(resolved, sort_keys=True, default=str).encode()
    ).hexdigest()
    return SettingsSnapshot(resolved, fingerprint)


class ReconfigurableAssembly[T]:
    """Hold one built assembly, rebuilding it only when settings change."""

    def __init__(
        self,
        database: Database,
        builder: Callable[[dict[str, object]], Awaitable[T]],
        *,
        retire: Callable[[T], Awaitable[None]] | None = None,
        initial: T | None = None,
    ) -> None:
        self._database = database
        self._builder = builder
        self._retire = retire
        self._assembly: T | None = initial
        self._fingerprint: str | None = None
        self._lock = asyncio.Lock()

    @property
    def assembly(self) -> T | None:
        return self._assembly

    async def current(self) -> T:
        """Return the up-to-date assembly, rebuilding after settings changes."""

        try:
            snapshot = await read_settings_snapshot(self._database)
        except Exception as error:  # noqa: BLE001 - never block jobs on settings reads
            LOGGER.warning(
                "settings_read_failed", extra={"error": str(error)[:200]}
            )
            snapshot = None
        async with self._lock:
            if snapshot is not None and snapshot.fingerprint != self._fingerprint:
                previous, self._assembly = self._assembly, await self._builder(
                    snapshot.values
                )
                self._fingerprint = snapshot.fingerprint
                if previous is not None and self._retire is not None:
                    await self._retire(previous)
                LOGGER.info("worker_assembly_rebuilt")
            assert self._assembly is not None
            return self._assembly


class HotReloadExecutor[AssemblyT]:
    """Stable JobExecutor facade over a reconfigurable AnalysisJobExecutor."""

    def __init__(
        self,
        assemblies: ReconfigurableAssembly[AssemblyT],
        execute: Callable[
            [AssemblyT, Job, asyncio.Event], Awaitable[WorkerResult]
        ],
    ) -> None:
        self._assemblies = assemblies
        self._execute = execute

    async def execute(self, job: Job, cancellation: asyncio.Event) -> WorkerResult:
        return await self._execute(await self._assemblies.current(), job, cancellation)


class HotReloadSettlementHook[AssemblyT]:
    """Stable settlement facade over a reconfigurable settlement hook."""

    def __init__(
        self,
        assemblies: ReconfigurableAssembly[AssemblyT],
        settle: Callable[[AssemblyT, Repositories, Job, WorkerResult], Awaitable[None]],
    ) -> None:
        self._assemblies = assemblies
        self._settle = settle

    async def after_terminal(
        self, repositories: Repositories, job: Job, result: WorkerResult
    ) -> None:
        await self._settle(await self._assemblies.current(), repositories, job, result)
