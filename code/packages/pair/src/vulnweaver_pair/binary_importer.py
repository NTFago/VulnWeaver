"""Import normalized binary analysis facts into the relational PAIR graph."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import cast

from vulnweaver_contracts import (
    BinaryAnalysisResult,
    BinaryFunction,
    BinaryLocation,
    BinaryXref,
    BinaryXrefType,
    JsonObject,
    PairEdge,
    PairEdgeType,
    PairFunction,
    PairNode,
    PairNodeKind,
    PairRaw,
    SchemaVersion,
    ToolIdentity,
    validate_contract,
)
from vulnweaver_persistence import Database

_MAX_DISASSEMBLY_PER_FUNCTION = 512


class BinaryPairImportError(ValueError):
    """A normalized binary result cannot be represented as a consistent PAIR graph."""


@dataclass(frozen=True, slots=True)
class BinaryPairImportSummary:
    artifact_version_id: str
    analyzed_artifact_version_id: str
    functions: int
    nodes: int
    edges: int
    raw_id: str


@dataclass(frozen=True, slots=True)
class _FunctionRecord:
    source: BinaryFunction
    pair: PairFunction
    node_id: str


class BinaryPairImporter:
    """Build deterministic PAIR functions/nodes/edges from one immutable binary result."""

    def __init__(
        self,
        database: Database,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._database = database
        self._clock = clock or (lambda: datetime.now(UTC))

    async def import_binary_result(
        self,
        result: BinaryAnalysisResult,
        *,
        raw_object_ref: str,
        tool: ToolIdentity,
        created_at: str | None = None,
    ) -> BinaryPairImportSummary:
        try:
            validate_contract("BinaryAnalysisResult", result)
        except ValueError as error:
            raise BinaryPairImportError(
                "binary analysis result does not satisfy the public contract"
            ) from error
        graph_version_id = result["artifact_version_id"]
        analyzed_version_id = result["analyzed_artifact_version_id"]
        raw_id = _stable_id(
            "pair-raw",
            graph_version_id,
            analyzed_version_id,
            tool["name"],
            tool["version"],
        )
        timestamp = created_at or _timestamp(self._clock())
        functions, nodes, records = _functions_and_nodes(result, raw_id)
        instruction_nodes, instruction_functions = _instruction_nodes(result, records, raw_id)
        block_nodes, block_functions = _basic_block_nodes(result, records, raw_id)
        nodes.extend(block_nodes)
        nodes.extend(instruction_nodes)
        edges, external_nodes = _binary_edges(
            result,
            records,
            block_nodes=block_nodes,
            block_functions=block_functions,
            instruction_nodes=instruction_nodes,
            instruction_functions=instruction_functions,
            raw_id=raw_id,
        )
        nodes.extend(external_nodes)
        raw = PairRaw(
            schema_version=SchemaVersion.VALUE_1_0_0,
            id=raw_id,
            artifact_version_id=graph_version_id,
            tool=tool,
            format="binary-analysis-result",
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
        return BinaryPairImportSummary(
            artifact_version_id=graph_version_id,
            analyzed_artifact_version_id=analyzed_version_id,
            functions=len(functions),
            nodes=len(nodes),
            edges=len(edges),
            raw_id=raw_id,
        )


def _functions_and_nodes(
    result: BinaryAnalysisResult,
    raw_id: str,
) -> tuple[list[PairFunction], list[PairNode], list[_FunctionRecord]]:
    graph_version_id = result["artifact_version_id"]
    pseudocode_by_address: dict[int, list[JsonObject]] = {}
    for item in result["pseudocode"]:
        pseudocode_by_address.setdefault(item["address"], []).append(cast(JsonObject, dict(item)))
    symbolic_by_address = {
        item["function_address"]: cast(JsonObject, dict(item)) for item in result["symbolic_facts"]
    }
    # Bounded per-function disassembly listing so downstream auditors can work
    # from instruction text when a function has no decompiler output.
    instructions_by_name: dict[str, list[JsonObject]] = {}
    for item in result["instructions"]:
        name = item.get("function_name")
        if not isinstance(name, str) or not name:
            continue
        bucket = instructions_by_name.setdefault(name, [])
        if len(bucket) < _MAX_DISASSEMBLY_PER_FUNCTION:
            bucket.append(cast(JsonObject, dict(item)))
    functions: list[PairFunction] = []
    nodes: list[PairNode] = []
    records: list[_FunctionRecord] = []
    for source in sorted(result["functions"], key=lambda item: (item["address"], item["name"])):
        function_id = _stable_id(
            "pair-function",
            graph_version_id,
            result["analyzed_artifact_version_id"],
            str(source["address"]),
            source["name"],
        )
        node_id = _stable_id("pair-node", function_id, "function")
        location = _location(
            result,
            source["address"],
            _resolved_file_offset(result, source["address"], source["file_offset"]),
            source["address"] + source["size"] if source["size"] else None,
        )
        attributes = cast(
            JsonObject,
            {
                "pair_raw_id": raw_id,
                "analyzed_artifact_version_id": result["analyzed_artifact_version_id"],
                "format": str(result["format"]),
                "architecture": str(result["architecture"]),
                "source_attributes": source["attributes"],
                "pseudocode": pseudocode_by_address.get(source["address"], []),
                "disassembly": instructions_by_name.get(source["name"], []),
                "symbolic_fact": symbolic_by_address.get(source["address"]),
            },
        )
        pair_function = PairFunction(
            schema_version=SchemaVersion.VALUE_1_0_0,
            id=function_id,
            artifact_version_id=graph_version_id,
            name=source["name"],
            symbol=source["name"],
            language=str(result["architecture"]),
            source_location=None,
            binary_location=location,
            signature=None,
            attributes=attributes,
        )
        functions.append(pair_function)
        nodes.append(
            PairNode(
                schema_version=SchemaVersion.VALUE_1_0_0,
                id=node_id,
                artifact_version_id=graph_version_id,
                function_id=function_id,
                kind=PairNodeKind.FUNCTION,
                location=location,
                attributes=cast(
                    JsonObject,
                    {
                        "name": source["name"],
                        "pair_raw_id": raw_id,
                        "analyzed_artifact_version_id": result["analyzed_artifact_version_id"],
                    },
                ),
            )
        )
        records.append(_FunctionRecord(source=source, pair=pair_function, node_id=node_id))
    return functions, nodes, records


def _instruction_nodes(
    result: BinaryAnalysisResult,
    records: list[_FunctionRecord],
    raw_id: str,
) -> tuple[list[PairNode], dict[int, str | None]]:
    nodes: list[PairNode] = []
    function_ids: dict[int, str | None] = {}
    for instruction in sorted(result["instructions"], key=lambda item: item["address"]):
        record = _resolve_function(records, instruction["address"], instruction["function_name"])
        function_id = record.pair["id"] if record is not None else None
        node_id = _stable_id(
            "pair-node",
            result["artifact_version_id"],
            result["analyzed_artifact_version_id"],
            "instruction",
            str(instruction["address"]),
        )
        nodes.append(
            PairNode(
                schema_version=SchemaVersion.VALUE_1_0_0,
                id=node_id,
                artifact_version_id=result["artifact_version_id"],
                function_id=function_id,
                kind=PairNodeKind.INSTRUCTION,
                location=_location(
                    result,
                    instruction["address"],
                    _resolved_file_offset(
                        result, instruction["address"], instruction["file_offset"]
                    ),
                    instruction["address"] + max(1, len(instruction["bytes"]) // 2),
                ),
                attributes=cast(
                    JsonObject,
                    {
                        "bytes": instruction["bytes"],
                        "mnemonic": instruction["mnemonic"],
                        "operands": instruction["operands"],
                        "function_name": instruction["function_name"],
                        "pair_raw_id": raw_id,
                    },
                ),
            )
        )
        function_ids[instruction["address"]] = function_id
    return nodes, function_ids


def _basic_block_nodes(
    result: BinaryAnalysisResult,
    records: list[_FunctionRecord],
    raw_id: str,
) -> tuple[list[PairNode], dict[int, str | None]]:
    nodes: list[PairNode] = []
    function_ids: dict[int, str | None] = {}
    for block in sorted(result["basic_blocks"], key=lambda item: item["start_address"]):
        record = _resolve_function(records, block["start_address"], block["function_name"])
        function_id = record.pair["id"] if record is not None else None
        node_id = _stable_id(
            "pair-node",
            result["artifact_version_id"],
            result["analyzed_artifact_version_id"],
            "basic-block",
            str(block["start_address"]),
        )
        nodes.append(
            PairNode(
                schema_version=SchemaVersion.VALUE_1_0_0,
                id=node_id,
                artifact_version_id=result["artifact_version_id"],
                function_id=function_id,
                kind=PairNodeKind.BASIC_BLOCK,
                location=_location(
                    result,
                    block["start_address"],
                    _resolved_file_offset(result, block["start_address"], None),
                    block["end_address"],
                ),
                attributes=cast(
                    JsonObject,
                    {
                        "function_name": block["function_name"],
                        "successor_addresses": block["successor_addresses"],
                        "pair_raw_id": raw_id,
                    },
                ),
            )
        )
        function_ids[block["start_address"]] = function_id
    return nodes, function_ids


def _binary_edges(
    result: BinaryAnalysisResult,
    records: list[_FunctionRecord],
    *,
    block_nodes: list[PairNode],
    block_functions: dict[int, str | None],
    instruction_nodes: list[PairNode],
    instruction_functions: dict[int, str | None],
    raw_id: str,
) -> tuple[list[PairEdge], list[PairNode]]:
    del block_functions, instruction_functions
    block_by_address = _nodes_by_address(block_nodes)
    instruction_by_address = _nodes_by_address(instruction_nodes)
    function_by_address = {record.source["address"]: record.node_id for record in records}
    edges: list[PairEdge] = []
    external_nodes: dict[int, PairNode] = {}

    for block in result["basic_blocks"]:
        source = block_by_address.get(block["start_address"])
        if source is None:
            continue
        for target_address in block["successor_addresses"]:
            target = (
                block_by_address.get(target_address)
                or instruction_by_address.get(target_address)
                or function_by_address.get(target_address)
                or _external_node(
                    result,
                    target_address,
                    None,
                    raw_id,
                    external_nodes,
                )["id"]
            )
            edges.append(
                _edge(
                    result,
                    source,
                    target,
                    PairEdgeType.CONTROL_FLOW,
                    "binary-control-flow",
                    raw_id,
                    {
                        "source_address": block["start_address"],
                        "target_address": target_address,
                    },
                )
            )

    for xref in result["xrefs"]:
        xref_type = BinaryXrefType(xref["type"])
        source = (
            instruction_by_address.get(xref["source_address"])
            or block_by_address.get(xref["source_address"])
            or _containing_function_node(records, xref["source_address"])
        )
        if source is None:
            source = _external_node(
                result,
                xref["source_address"],
                xref["source_function"],
                raw_id,
                external_nodes,
            )["id"]
        target = _target_node(
            result,
            xref,
            xref_type,
            records,
            block_by_address,
            instruction_by_address,
            function_by_address,
            raw_id,
            external_nodes,
        )
        edge_type = PairEdgeType.CALL if xref_type is BinaryXrefType.CALL else PairEdgeType.XREF
        scope = f"binary-{xref_type.value}"
        edges.append(
            _edge(
                result,
                source,
                target,
                edge_type,
                scope,
                raw_id,
                {
                    "source_address": xref["source_address"],
                    "target_address": xref["target_address"],
                    "source_function": xref["source_function"],
                    "target_symbol": xref["target_symbol"],
                    "xref_type": xref_type.value,
                },
            )
        )
    return _deduplicate_edges(edges), list(external_nodes.values())


def _target_node(
    result: BinaryAnalysisResult,
    xref: BinaryXref,
    xref_type: BinaryXrefType,
    records: list[_FunctionRecord],
    block_by_address: dict[int, str],
    instruction_by_address: dict[int, str],
    function_by_address: dict[int, str],
    raw_id: str,
    external_nodes: dict[int, PairNode],
) -> str:
    if xref_type is BinaryXrefType.CALL:
        function = function_by_address.get(xref["target_address"])
        if function is not None:
            return function
        contained = _containing_function_node(records, xref["target_address"])
        if contained is not None:
            return contained
    target = block_by_address.get(xref["target_address"]) or instruction_by_address.get(
        xref["target_address"]
    )
    if target is not None:
        return target
    return _external_node(
        result,
        xref["target_address"],
        xref["target_symbol"],
        raw_id,
        external_nodes,
    )["id"]


def _external_node(
    result: BinaryAnalysisResult,
    address: int,
    symbol: str | None,
    raw_id: str,
    nodes: dict[int, PairNode],
) -> PairNode:
    existing = nodes.get(address)
    if existing is not None:
        return existing
    node = PairNode(
        schema_version=SchemaVersion.VALUE_1_0_0,
        id=_stable_id(
            "pair-node",
            result["artifact_version_id"],
            result["analyzed_artifact_version_id"],
            "external",
            str(address),
        ),
        artifact_version_id=result["artifact_version_id"],
        function_id=None,
        kind=PairNodeKind.MEMORY_OBJECT,
        location=_location(
            result,
            address,
            _resolved_file_offset(result, address, None),
            None,
        ),
        attributes=cast(
            JsonObject,
            {"symbol": symbol, "external": True, "pair_raw_id": raw_id},
        ),
    )
    nodes[address] = node
    return node


def _edge(
    result: BinaryAnalysisResult,
    source: str,
    target: str,
    edge_type: PairEdgeType,
    scope: str,
    raw_id: str,
    attributes: dict[str, object],
) -> PairEdge:
    return PairEdge(
        schema_version=SchemaVersion.VALUE_1_0_0,
        id=_stable_id(
            "pair-edge",
            result["artifact_version_id"],
            source,
            target,
            edge_type.value,
            scope,
        ),
        artifact_version_id=result["artifact_version_id"],
        source_node_id=source,
        target_node_id=target,
        type=edge_type,
        scope=scope,
        confidence=1.0,
        evidence_id=None,
        attributes=cast(JsonObject, {**attributes, "pair_raw_id": raw_id}),
    )


def _deduplicate_edges(edges: list[PairEdge]) -> list[PairEdge]:
    values: dict[tuple[str, str, PairEdgeType, str], PairEdge] = {}
    for edge in edges:
        key = (
            edge["source_node_id"],
            edge["target_node_id"],
            edge["type"],
            edge["scope"],
        )
        values.setdefault(key, edge)
    return sorted(values.values(), key=lambda item: item["id"])


def _nodes_by_address(nodes: list[PairNode]) -> dict[int, str]:
    output: dict[int, str] = {}
    for node in nodes:
        location = node["location"]
        if location is not None and "virtual_address" in location:
            output.setdefault(location["virtual_address"], node["id"])
    return output


def _resolve_function(
    records: list[_FunctionRecord], address: int, name: str | None
) -> _FunctionRecord | None:
    candidates = [record for record in records if name and record.source["name"] == name]
    contained = [record for record in candidates if _contains(record.source, address)]
    if len(contained) == 1:
        return contained[0]
    all_contained = [record for record in records if _contains(record.source, address)]
    return all_contained[0] if len(all_contained) == 1 else None


def _containing_function_node(records: list[_FunctionRecord], address: int) -> str | None:
    record = _resolve_function(records, address, None)
    return record.node_id if record is not None else None


def _contains(function: BinaryFunction, address: int) -> bool:
    if function["size"] == 0:
        return function["address"] == address
    return function["address"] <= address < function["address"] + function["size"]


def _resolved_file_offset(
    result: BinaryAnalysisResult,
    address: int,
    provided: int | None,
) -> int | None:
    if provided is not None:
        return provided
    for section in result["sections"]:
        start = section["virtual_address"]
        delta = address - start
        if 0 <= delta < section["file_size"]:
            return section["file_offset"] + delta
    return None


def _location(
    result: BinaryAnalysisResult,
    address: int,
    file_offset: int | None,
    instruction_end: int | None,
) -> BinaryLocation:
    location = BinaryLocation(
        artifact_version_id=result["analyzed_artifact_version_id"],
        image_base=result["image_base"],
        virtual_address=address,
        file_offset=file_offset,
    )
    if instruction_end is not None:
        location["instruction_end"] = max(address, instruction_end)
    return location


def _stable_id(prefix: str, *parts: str) -> str:
    digest = hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()[:32]
    return f"{prefix}:{digest}"


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise BinaryPairImportError("PAIR timestamps require timezone-aware datetime")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise BinaryPairImportError("PAIR timestamps require timezone-aware datetime")
    return parsed.astimezone(UTC)
