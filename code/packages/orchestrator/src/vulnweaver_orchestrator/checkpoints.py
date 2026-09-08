"""Durable checkpoint contracts for resumable orchestration."""

from __future__ import annotations

import copy
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC
from typing import Protocol, cast

from vulnweaver_contracts import JsonObject
from vulnweaver_persistence import Database, StoredCheckpoint


@dataclass(frozen=True, slots=True)
class Checkpoint:
    task_id: str
    sequence: int
    node: str
    state: JsonObject
    created_at: str


class CheckpointConflict(RuntimeError):
    """A checkpoint sequence was already used with different state."""


class CheckpointStore(Protocol):
    async def save(
        self, task_id: str, node: str, state: Mapping[str, object], *, created_at: str
    ) -> Checkpoint: ...

    async def latest(self, task_id: str) -> Checkpoint | None: ...

    async def list(self, task_id: str) -> Sequence[Checkpoint]: ...


class InMemoryCheckpointStore:
    """Deterministic checkpoint store used by unit tests and local dry runs."""

    def __init__(self) -> None:
        self._checkpoints: dict[str, list[Checkpoint]] = {}

    async def save(
        self, task_id: str, node: str, state: Mapping[str, object], *, created_at: str
    ) -> Checkpoint:
        entries = self._checkpoints.setdefault(task_id, [])
        value = Checkpoint(
            task_id=task_id,
            sequence=len(entries),
            node=node,
            state=cast(JsonObject, copy.deepcopy(dict(state))),
            created_at=created_at,
        )
        entries.append(value)
        return copy.deepcopy(value)

    async def latest(self, task_id: str) -> Checkpoint | None:
        entries = self._checkpoints.get(task_id, [])
        return copy.deepcopy(entries[-1]) if entries else None

    async def list(self, task_id: str) -> Sequence[Checkpoint]:
        return tuple(copy.deepcopy(entry) for entry in self._checkpoints.get(task_id, []))


class PostgresCheckpointStore:
    """Database-backed checkpoint adapter with transaction-scoped sequencing."""

    def __init__(self, database: Database) -> None:
        self._database = database

    async def save(
        self, task_id: str, node: str, state: Mapping[str, object], *, created_at: str
    ) -> Checkpoint:
        from datetime import datetime

        parsed = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("checkpoint timestamps require an explicit timezone")
        async with self._database.transaction() as repositories:
            stored = await repositories.checkpoints.append(
                task_id, node, dict(state), created_at=parsed
            )
        return _checkpoint_from_stored(stored)

    async def latest(self, task_id: str) -> Checkpoint | None:
        async with self._database.transaction() as repositories:
            stored = await repositories.checkpoints.latest(task_id)
        return _checkpoint_from_stored(stored) if stored is not None else None

    async def list(self, task_id: str) -> Sequence[Checkpoint]:
        async with self._database.transaction() as repositories:
            stored = await repositories.checkpoints.list_for_task(task_id)
        return tuple(_checkpoint_from_stored(item) for item in stored)


def _checkpoint_from_stored(value: StoredCheckpoint) -> Checkpoint:
    return Checkpoint(
        task_id=value.task_id,
        sequence=value.sequence,
        node=value.node,
        state=cast(JsonObject, value.state),
        created_at=value.created_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
    )
