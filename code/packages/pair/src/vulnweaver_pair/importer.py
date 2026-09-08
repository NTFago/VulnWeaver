"""Build deterministic PAIR rows from the T12 source index."""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import cast

from vulnweaver_contracts import (
    JsonObject,
    PairEdge,
    PairEdgeType,
    PairFunction,
    PairNode,
    PairNodeKind,
    PairRaw,
    SchemaVersion,
    SourceFunction,
    SourceImportResult,
    ToolIdentity,
)
from vulnweaver_persistence import Database


class PairImportError(ValueError):
    """The source index cannot be safely converted to PAIR rows."""


@dataclass(frozen=True, slots=True)
class PairImportSummary:
    artifact_version_id: str
    functions: int
    nodes: int
    edges: int
    raw_id: str


class SourcePairImporter:
    """Import one immutable source index into the relational PAIR graph."""

    def __init__(
        self,
        database: Database,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._database = database
        self._clock = clock or (lambda: datetime.now(UTC))

    async def import_source_result(
        self,
        result: SourceImportResult,
        *,
        raw_object_ref: str,
        tool: ToolIdentity,
        created_at: str | None = None,
    ) -> PairImportSummary:
        artifact_version_id = result["artifact_version_id"]
        raw_id = _stable_id("pair-raw", artifact_version_id, tool["name"], tool["version"])
        timestamp = created_at or _timestamp(self._clock())
        functions, nodes, source_to_node = _functions_and_nodes(result, raw_id)
        edges = _call_edges(result, source_to_node, raw_id)
        raw = PairRaw(
            schema_version=SchemaVersion.VALUE_1_0_0,
            id=raw_id,
            artifact_version_id=artifact_version_id,
            tool=tool,
            format="source-import-result",
            object_ref=raw_object_ref,
            created_at=timestamp,
        )
        async with self._database.transaction() as repositories:
            await repositories.pair.import_graph(
                functions,
                nodes,
                edges,
                raw,
                created_at=_parse_timestamp(timestamp),
            )
        return PairImportSummary(
            artifact_version_id=artifact_version_id,
            functions=len(functions),
            nodes=len(nodes),
            edges=len(edges),
            raw_id=raw_id,
        )


def _functions_and_nodes(
    result: SourceImportResult,
    raw_id: str,
) -> tuple[list[PairFunction], list[PairNode], dict[str, str]]:
    functions: list[PairFunction] = []
    nodes: list[PairNode] = []
    source_to_node: dict[str, str] = {}
    for source_function in result["functions"]:
        function_id = _stable_id(
            "pair-function", result["artifact_version_id"], source_function["id"]
        )
        node_id = _stable_id("pair-node", function_id)
        source_to_node[source_function["id"]] = node_id
        attributes = {
            "kind": source_function["kind"],
            "qualified_name": source_function["qualified_name"],
            "parameters": source_function["parameters"],
            "pair_raw_id": raw_id,
        }
        functions.append(
            PairFunction(
                schema_version=SchemaVersion.VALUE_1_0_0,
                id=function_id,
                artifact_version_id=result["artifact_version_id"],
                name=source_function["name"],
                symbol=source_function["qualified_name"],
                language=source_function["language"],
                source_location=source_function["location"],
                binary_location=None,
                signature=_signature(source_function),
                attributes=cast(JsonObject, attributes),
            )
        )
        nodes.append(
            PairNode(
                schema_version=SchemaVersion.VALUE_1_0_0,
                id=node_id,
                artifact_version_id=result["artifact_version_id"],
                function_id=function_id,
                kind=PairNodeKind.FUNCTION,
                location=source_function["location"],
                attributes=cast(
                    JsonObject,
                    {"name": source_function["name"], "pair_raw_id": raw_id},
                ),
            )
        )
    return functions, nodes, source_to_node


def _call_edges(
    result: SourceImportResult, source_to_node: Mapping[str, str], raw_id: str
) -> list[PairEdge]:
    by_name: dict[str, str] = {}
    for source_function in result["functions"]:
        node_id = source_to_node[source_function["id"]]
        by_name.setdefault(source_function["name"], node_id)
        by_name.setdefault(source_function["qualified_name"], node_id)
    edges: list[PairEdge] = []
    for call in result["calls"]:
        target = by_name.get(call["callee"])
        if target is None:
            target = next(
                (
                    node_id
                    for name, node_id in by_name.items()
                    if name.endswith(f".{call['callee']}")
                ),
                None,
            )
        source = source_to_node.get(call["caller_id"])
        if source is None or target is None:
            continue
        edge_id = _stable_id(
            "pair-edge",
            result["artifact_version_id"],
            source,
            target,
            call["location"]["path"],
            str(call["location"]["start_line"]),
        )
        edges.append(
            PairEdge(
                schema_version=SchemaVersion.VALUE_1_0_0,
                id=edge_id,
                artifact_version_id=result["artifact_version_id"],
                source_node_id=source,
                target_node_id=target,
                type=PairEdgeType.CALL,
                scope="source",
                confidence=1.0,
                evidence_id=None,
                attributes=cast(
                    JsonObject, {"callee": call["callee"], "location": call["location"]}
                ),
            )
        )
    return edges


def _signature(source_function: SourceFunction) -> str:
    names: list[str] = []
    for parameter in source_function["parameters"]:
        names.append(parameter["type"] or parameter["name"] or "?")
    return f"{source_function['name']}({', '.join(names)})"


def _stable_id(prefix: str, *parts: str) -> str:
    digest = hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()[:32]
    return f"{prefix}:{digest}"


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("PAIR timestamps require timezone-aware datetime")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)
