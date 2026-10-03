"""CR-07: the SQL-pushed neighborhood walk stays correct at multiple depths.

The recursive-CTE rewrite replaced a full-graph transfer into Python; these
tests pin the walk semantics the projections and call paths rely on: the seed
is every node of the anchor function, each depth level expands one hop across
both edge directions, and the function set follows the reached nodes.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from uuid import uuid4

from vulnweaver_contracts import PairEdge, PairFunction, PairNode
from vulnweaver_persistence import Database, DatabaseSettings

from tests.persistence.factories import artifact, artifact_version, project

NOW = datetime.now(UTC)


def _function(identifier: str, version_id: str, name: str) -> PairFunction:
    return PairFunction(
        schema_version="1.0.0",
        id=identifier,
        artifact_version_id=version_id,
        name=name,
        symbol=name,
        language="x86_64",
        source_location=None,
        binary_location={
            "artifact_version_id": version_id,
            "image_base": 0x400000,
            "virtual_address": 0x1000,
            "file_offset": 0x1000,
        },
        signature=None,
        attributes={},
    )


def _node(identifier: str, version_id: str, function_id: str, kind: str) -> PairNode:
    return PairNode(
        schema_version="1.0.0",
        id=identifier,
        artifact_version_id=version_id,
        function_id=function_id,
        kind=kind,
        location=None,
        attributes={},
    )


def _edge(identifier: str, version_id: str, source: str, target: str) -> PairEdge:
    return PairEdge(
        schema_version="1.0.0",
        id=identifier,
        artifact_version_id=version_id,
        source_node_id=source,
        target_node_id=target,
        type="call",
        scope="binary-call",
        confidence=1.0,
        evidence_id=None,
        attributes={},
    )


def _chain(version_id: str) -> tuple[list[PairFunction], list[PairNode], list[PairEdge]]:
    """f1 -> f2 -> f3 call chain, each function holding one function node."""

    functions = [
        _function(f"pair-function:{name}", version_id, name)
        for name in ("f1", "f2", "f3")
    ]
    nodes = [
        _node(f"pair-node:{name}", version_id, f"pair-function:{name}", "function")
        for name in ("f1", "f2", "f3")
    ]
    edges = [
        _edge("pair-edge:e1", version_id, "pair-node:f1", "pair-node:f2"),
        _edge("pair-edge:e2", version_id, "pair-node:f2", "pair-node:f3"),
    ]
    return functions, nodes, edges


def test_neighborhood_walks_one_hop_per_depth_level(persistence_database_url: str) -> None:
    async def scenario() -> None:
        suffix = uuid4().hex
        version_id = f"artifact-version:{suffix}"
        database = Database(DatabaseSettings(persistence_database_url))
        functions, nodes, edges = _chain(version_id)
        try:
            async with database.transaction() as repositories:
                await repositories.projects.add(project(f"project:{suffix}"))
                await repositories.artifacts.add(
                    artifact(
                        f"artifact:{suffix}",
                        project_id=f"project:{suffix}",
                        current_version_id=version_id,
                    )
                )
                await repositories.artifacts.add_version(
                    artifact_version(version_id, artifact_id=f"artifact:{suffix}")
                )
                await repositories.pair.import_graph(functions, nodes, edges, None, created_at=NOW)
                assert await repositories.pair.has_functions(version_id) is True

                one_hop = await repositories.pair.neighborhood(
                    version_id, "pair-function:f1", depth=1
                )
                assert {function["name"] for function in one_hop["functions"]} == {"f1", "f2"}
                assert {edge["id"] for edge in one_hop["edges"]} == {"pair-edge:e1"}

                two_hops = await repositories.pair.neighborhood(
                    version_id, "pair-function:f1", depth=2
                )
                assert {function["name"] for function in two_hops["functions"]} == {
                    "f1",
                    "f2",
                    "f3",
                }
                assert {edge["id"] for edge in two_hops["edges"]} == {
                    "pair-edge:e1",
                    "pair-edge:e2",
                }

                # The walk reaches the anchor through incoming edges too.
                incoming = await repositories.pair.neighborhood(
                    version_id, "pair-function:f3", depth=1
                )
                assert {function["name"] for function in incoming["functions"]} == {"f2", "f3"}

            # A version with no pair rows reports no functions without loading.
            async with database.transaction() as repositories:
                assert await repositories.pair.has_functions("artifact-version:missing") is False
        finally:
            await database.dispose()

    asyncio.run(scenario())
