"""Heuristics for identifying control-flow flattening in extracted facts."""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from vulnweaver_contracts import BinaryBasicBlock, BinaryXref


@dataclass(frozen=True, slots=True)
class ObfuscationAssessment:
    function_name: str
    flattened: bool
    score: float
    dispatcher_blocks: int
    indirect_jumps: int
    reason: str


def _control_returns_to(adjacency: Mapping[int, Sequence[int]], origin: int) -> bool:
    """Whether control can leave `origin` and arrive back at it."""
    seen: set[int] = set()
    pending = list(adjacency.get(origin, ()))
    while pending:
        address = pending.pop()
        if address == origin:
            return True
        if address in seen:
            continue
        seen.add(address)
        pending.extend(adjacency.get(address, ()))
    return False


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
        function_name = block.get("function_name")
        if function_name is not None:
            blocks_by_function[function_name].append(block)
    jumps_by_function: Counter[str] = Counter()
    for xref in xrefs:
        source_function = xref.get("source_function")
        if (
            xref["type"] == "jump"
            and xref.get("target_symbol") is None
            and source_function is not None
        ):
            jumps_by_function[source_function] += 1
    results: list[ObfuscationAssessment] = []
    for function_name in sorted(blocks_by_function):
        blocks = blocks_by_function[function_name]
        addresses = {block["start_address"] for block in blocks}
        adjacency = {
            block["start_address"]: [
                successor
                for successor in block["successor_addresses"]
                if successor in addresses
            ]
            for block in blocks
        }

        # A dispatcher is a wide block that control returns to.  Fan-out alone
        # also describes an ordinary `switch`, whose dispatcher is entered once
        # and never revisited; flattening loops back through its dispatcher
        # because every case body ends by re-entering it.
        dispatcher_blocks = sum(
            1
            for block in blocks
            if len(block["successor_addresses"]) >= min_dispatcher_successors
            and _control_returns_to(adjacency, block["start_address"])
        )
        indirect_jumps = jumps_by_function[function_name]
        jump_ratio = indirect_jumps / max(1, len(blocks))
        # The dispatcher's presence is the signal.  Scoring its *density* was the
        # earlier mistake: a real flattened function carries one dispatcher among
        # many case blocks, so it measured 1/14 and could never reach a threshold
        # that only a single-block function satisfies.
        score = min(1.0, 0.7 * min(1.0, float(dispatcher_blocks)) + 0.3 * min(1.0, jump_ratio))
        flattened = score >= min_score and dispatcher_blocks > 0
        reason = (
            f"{dispatcher_blocks} of {len(blocks)} blocks fan out to at least "
            f"{min_dispatcher_successors} successors and are re-entered; "
            f"{indirect_jumps} indirect jumps"
        )
        results.append(
            ObfuscationAssessment(
                function_name, flattened, score, dispatcher_blocks, indirect_jumps, reason
            )
        )
    return tuple(results)
