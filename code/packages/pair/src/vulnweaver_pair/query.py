"""PAIR source query facade."""

from __future__ import annotations

from dataclasses import dataclass
from typing import cast

from vulnweaver_contracts import PairEdge, PairFunction, PairNode
from vulnweaver_persistence import Database


@dataclass(frozen=True, slots=True)
class PairNeighborhood:
    functions: list[PairFunction]
    nodes: list[PairNode]
    edges: list[PairEdge]


class PairQueryService:
    def __init__(self, database: Database) -> None:
        self._database = database

    async def list_functions(self, artifact_version_id: str) -> list[PairFunction]:
        async with self._database.transaction() as repositories:
            return await repositories.pair.list_functions(artifact_version_id)

    async def functions_at_location(
        self, artifact_version_id: str, path: str, line: int
    ) -> list[PairFunction]:
        async with self._database.transaction() as repositories:
            return await repositories.pair.functions_at_location(artifact_version_id, path, line)

    async def neighborhood(
        self, artifact_version_id: str, function_id: str, *, depth: int = 1
    ) -> PairNeighborhood:
        async with self._database.transaction() as repositories:
            value = await repositories.pair.neighborhood(
                artifact_version_id, function_id, depth=depth
            )
        return PairNeighborhood(
            functions=cast(list[PairFunction], value["functions"]),
            nodes=cast(list[PairNode], value["nodes"]),
            edges=cast(list[PairEdge], value["edges"]),
        )
