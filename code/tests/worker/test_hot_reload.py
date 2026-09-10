"""Hot-reload semantics for the settings-driven worker assembly."""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

import pytest
import vulnweaver_analysis_worker.hot_reload as hot_reload
from vulnweaver_analysis_worker.hot_reload import (
    HotReloadExecutor,
    HotReloadSettlementHook,
    ReconfigurableAssembly,
    SettingsSnapshot,
)


@dataclass
class _FakeAssembly:
    generation: int
    closed: bool = False


SnapshotReader = Callable[[object], Awaitable[SettingsSnapshot | None]]


def _reader_for(values: dict[str, object] | None, *, error: bool = False) -> SnapshotReader:
    async def _read(database: object) -> SettingsSnapshot | None:
        if error:
            raise RuntimeError("database unreachable")
        if values is None:
            return None
        fingerprint = hashlib.sha256(
            json.dumps(values, sort_keys=True, default=str).encode()
        ).hexdigest()
        return SettingsSnapshot(values, fingerprint)

    return _read


def test_assembly_rebuilds_only_when_fingerprint_changes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        monkeypatch.setattr(hot_reload, "read_settings_snapshot", _reader_for({}))
        builds: list[int] = []
        retired: list[int] = []

        async def _build(values: dict[str, object]) -> _FakeAssembly:
            builds.append(len(builds) + 1)
            return _FakeAssembly(generation=builds[-1])

        async def _retire(assembly: _FakeAssembly) -> None:
            assembly.closed = True
            retired.append(assembly.generation)

        assemblies: ReconfigurableAssembly[_FakeAssembly] = ReconfigurableAssembly(
            object(), _build, retire=_retire  # type: ignore[arg-type]
        )
        first = await assemblies.current()
        second = await assemblies.current()
        assert first is second
        assert builds == [1]

        changed = {"tool_image_digests": {"afl_casr": "sha256:" + "a" * 64}}
        monkeypatch.setattr(hot_reload, "read_settings_snapshot", _reader_for(changed))
        third = await assemblies.current()
        assert third is not first
        assert first.closed is True
        assert builds == [1, 2]
        assert retired == [1]

    asyncio.run(scenario())


def test_settings_outage_keeps_last_assembly(monkeypatch: pytest.MonkeyPatch) -> None:
    async def scenario() -> None:
        async def _build(values: dict[str, object]) -> _FakeAssembly:
            return _FakeAssembly(generation=99)

        assemblies: ReconfigurableAssembly[_FakeAssembly] = ReconfigurableAssembly(
            object(), _build, initial=_FakeAssembly(generation=0)  # type: ignore[arg-type]
        )
        monkeypatch.setattr(
            hot_reload, "read_settings_snapshot", _reader_for(None, error=True)
        )
        # The real reader swallows database outages and returns None; the
        # assembly must keep serving the last-resolved instance.
        current = await assemblies.current()
        assert current.generation == 0

    asyncio.run(scenario())


def test_executor_and_settlement_facades_delegate_to_current(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        monkeypatch.setattr(hot_reload, "read_settings_snapshot", _reader_for({}))
        calls: list[tuple[str, int]] = []

        async def _build(values: dict[str, object]) -> _FakeAssembly:
            return _FakeAssembly(generation=2 if values else 1)

        assemblies: ReconfigurableAssembly[_FakeAssembly] = ReconfigurableAssembly(
            object(), _build  # type: ignore[arg-type]
        )

        async def _execute(assembly: _FakeAssembly, job: object, cancel: object) -> str:
            calls.append(("execute", assembly.generation))
            return "result"

        async def _settle(
            assembly: _FakeAssembly, repositories: object, job: object, result: object
        ) -> None:
            calls.append(("settle", assembly.generation))

        executor = HotReloadExecutor(assemblies, _execute)
        settlement = HotReloadSettlementHook(assemblies, _settle)
        job: dict[str, object] = {"id": "job:1"}
        assert await executor.execute(job, asyncio.Event()) == "result"
        await settlement.after_terminal({}, job, "result")  # type: ignore[arg-type]
        assert calls == [("execute", 1), ("settle", 1)]

        monkeypatch.setattr(hot_reload, "read_settings_snapshot", _reader_for({"x": 1}))
        await executor.execute(job, asyncio.Event())
        await settlement.after_terminal({}, job, "result")  # type: ignore[arg-type]
        assert calls[-2:] == [("execute", 2), ("settle", 2)]

    asyncio.run(scenario())


def test_fingerprint_distinguishes_values() -> None:
    def _fp(values: dict[str, object]) -> str:
        return hashlib.sha256(
            json.dumps(values, sort_keys=True, default=str).encode()
        ).hexdigest()

    assert _fp({"a": 1}) == _fp({"a": 1})
    assert _fp({"a": 1}) != _fp({"a": 2})
