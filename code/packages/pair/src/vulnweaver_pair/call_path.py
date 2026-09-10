"""Deterministic projection of a PAIR neighborhood into Finding call-path steps.

The steps are a bounded, read-only projection: one ``target`` step for the
anchored function plus its immediate ``caller``/``callee`` neighbours.  The
neighborhood is symmetric and carries every edge type, so call relations are
recovered by resolving ``call`` edges through the node-to-function map in both
directions.  Nothing here mutates the PAIR graph or the Finding.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Literal

from vulnweaver_contracts import (
    CallPathStep,
    PairEdge,
    PairEdgeType,
    PairFunction,
    PairNode,
)

MAX_CALL_PATH_STEPS = 64

CallPathRelation = Literal["target", "caller", "callee"]

_RELATION_ORDER: dict[CallPathRelation, int] = {"target": 0, "caller": 1, "callee": 2}


def build_call_path_steps(
    functions: Sequence[PairFunction],
    nodes: Sequence[PairNode],
    edges: Sequence[PairEdge],
    anchor_function_id: str,
    *,
    max_steps: int = MAX_CALL_PATH_STEPS,
) -> list[CallPathStep]:
    """Reduce one PAIR neighborhood to bounded, de-duplicated call-path steps."""
    if max_steps < 0:
        raise ValueError("call path step budget must not be negative")
    by_function = {function["id"]: function for function in functions}
    anchor = by_function.get(anchor_function_id)

    references: list[tuple[CallPathRelation, str]] = []
    seen: set[str] = set()
    if anchor is not None:
        references.append(("target", anchor_function_id))
        seen.add(anchor_function_id)

    node_function = {
        node["id"]: node["function_id"] for node in nodes if node["function_id"] is not None
    }
    for relation, function_id in _call_neighbours(edges, node_function, anchor_function_id):
        if function_id == anchor_function_id or function_id in seen:
            continue
        if function_id not in by_function:
            continue
        seen.add(function_id)
        references.append((relation, function_id))

    references.sort(
        key=lambda item: (
            _RELATION_ORDER[item[0]],
            by_function[item[1]]["name"],
            item[1],
        )
    )
    return [
        _step(relation, by_function[function_id])
        for relation, function_id in references[:max_steps]
    ]


def _call_neighbours(
    edges: Sequence[PairEdge],
    node_function: dict[str, str],
    anchor_function_id: str,
) -> list[tuple[CallPathRelation, str]]:
    """Return ``(relation, function_id)`` for every resolved ``call`` edge."""
    neighbours: list[tuple[CallPathRelation, str]] = []
    for edge in edges:
        # The contract type is an enum, but a row can surface the raw column
        # value, so compare by value rather than identity.
        if PairEdgeType(edge["type"]) is not PairEdgeType.CALL:
            continue
        source = node_function.get(edge["source_node_id"])
        target = node_function.get(edge["target_node_id"])
        # Binary call edges start at instruction or basic-block nodes, so both
        # endpoints must be resolved through the node-to-function map.
        if source == anchor_function_id and target is not None:
            neighbours.append(("callee", target))
        elif target == anchor_function_id and source is not None:
            neighbours.append(("caller", source))
    return neighbours


def _step(relation: CallPathRelation, function: PairFunction) -> CallPathStep:
    source = function["source_location"]
    binary = function["binary_location"]
    return CallPathStep(
        relation=relation,
        function_name=function["name"],
        path=source["path"] if source is not None else None,
        line=source["start_line"] if source is not None else None,
        address=binary["virtual_address"] if binary is not None else None,
    )
