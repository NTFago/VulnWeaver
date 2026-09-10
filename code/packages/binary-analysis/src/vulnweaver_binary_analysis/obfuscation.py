"""Heuristics for identifying control-flow flattening in extracted facts."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Mapping, Sequence

from vulnweaver_contracts import BinaryBasicBlock, BinaryXref


@dataclass(frozen=True, slots=True)
class ObfuscationAssessment:
    function_name: str
    flattened: bool
    score: float
    dispatcher_blocks: int
    indirect_jumps: int
    reason: str


def assess_control_flow_flattening(
    basic_blocks: Sequence[BinaryBasicBlock],
    xrefs: Sequence[BinaryXref],
    *,
    min_dispatcher_successors: int = 4,
    min_score: float = 0.55,
) -> tuple[ObfuscationAssessment, ...]:
    """Return bounded, explainable per-function flattening assessments.

    The heuristic combines dispatcher-like blocks (many successors) with
    indirect jump density. It is deliberately advisory and never establishes
    a security finding by itself.
    """
    if min_dispatcher_successors < 2 or not 0 < min_score <= 1:
        raise ValueError("invalid flattening heuristic thresholds")
    blocks_by_function: dict[str, list[BinaryBasicBlock]] = defaultdict(list)
    for block in basic_blocks:
        blocks_by_function[block["function_name"]].append(block)
    jumps_by_function: Counter[str] = Counter()
    for xref in xrefs:
        if xref["type"] == "jump" and xref.get("target_symbol") is None:
            jumps_by_function[xref["source_function"]] += 1
    results: list[ObfuscationAssessment] = []
    for function_name in sorted(blocks_by_function):
        blocks = blocks_by_function[function_name]
        dispatcher_blocks = sum(
            len(block["successor_addresses"]) >= min_dispatcher_successors
            for block in blocks
        )
        indirect_jumps = jumps_by_function[function_name]
        block_ratio = dispatcher_blocks / max(1, len(blocks))
        jump_ratio = indirect_jumps / max(1, len(blocks))
        score = min(1.0, 0.7 * block_ratio + 0.3 * min(1.0, jump_ratio))
        flattened = score >= min_score and dispatcher_blocks > 0
        reason = (
            f"{dispatcher_blocks}/{len(blocks)} blocks have at least "
            f"{min_dispatcher_successors} successors; {indirect_jumps} indirect jumps"
        )
        results.append(ObfuscationAssessment(function_name, flattened, score, dispatcher_blocks, indirect_jumps, reason))
    return tuple(results)
