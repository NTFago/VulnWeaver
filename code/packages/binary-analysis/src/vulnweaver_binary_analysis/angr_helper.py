# pyright: reportUnknownVariableType=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportUnknownLambdaType=false, reportArgumentType=false, reportUnnecessaryComparison=false
"""Optional subprocess helper for bounded angr CFGFast extraction."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


def main() -> None:
    # argv includes the executable name; the helper has nine positional
    # arguments after it (the limits, state budget, and target list).
    if len(sys.argv) != 10:
        raise SystemExit(
            "usage: angr_helper INPUT OUTPUT MAX_FUNCTIONS MAX_INSTRUCTIONS "
            "MAX_BLOCKS MAX_XREFS STEP_LIMIT STATE_LIMIT TARGETS"
        )
    source = Path(sys.argv[1]).resolve()
    output = Path(sys.argv[2]).resolve()
    function_limit = int(sys.argv[3])
    instruction_limit = int(sys.argv[4])
    block_limit = int(sys.argv[5])
    xref_limit = int(sys.argv[6])
    step_limit = int(sys.argv[7])
    state_limit = int(sys.argv[8])
    targets = tuple(sorted({int(value) for value in sys.argv[9].split(",") if value}))
    if (
        min(
            function_limit,
            instruction_limit,
            block_limit,
            xref_limit,
            step_limit,
            state_limit,
        )
        < 1
    ):
        raise SystemExit("analysis limits must be positive")
    if any(value < 0 for value in targets):
        raise SystemExit("target addresses must be non-negative")

    import angr  # type: ignore[import-not-found]  # Optional runtime dependency.

    project = angr.Project(str(source), auto_load_libs=False)
    cfg = project.analyses.CFGFast(normalize=True, data_references=True)
    functions: list[dict[str, Any]] = []
    instructions: list[dict[str, Any]] = []
    basic_blocks: list[dict[str, Any]] = []
    xrefs: list[dict[str, Any]] = []
    for function in sorted(cfg.kb.functions.values(), key=lambda item: int(item.addr))[
        :function_limit
    ]:
        functions.append(
            {
                "name": str(function.name),
                "address": int(function.addr),
                "size": int(function.size or 0),
                "attributes": {"source": "angr-cfgfast"},
            }
        )
        for block in function.blocks:
            node = cfg.model.get_any_node(block.addr)
            successors = [] if node is None else list(cfg.graph.successors(node))
            if len(basic_blocks) < block_limit:
                basic_blocks.append(
                    {
                        "function_name": str(function.name),
                        "start_address": int(block.addr),
                        "end_address": int(block.addr + block.size),
                        "successor_addresses": sorted(
                            {int(successor.addr) for successor in successors}
                        ),
                    }
                )
            for successor in successors:
                if len(xrefs) >= xref_limit:
                    break
                edge = cfg.graph.get_edge_data(node, successor) or {}
                jumpkind = str(edge.get("jumpkind") or "")
                try:
                    target_function = cfg.kb.functions.get_by_addr(int(successor.addr))
                except KeyError:
                    # CFG edges can target an intra-function block rather than
                    # a registered function entry; retain the xref either way.
                    target_function = None
                xrefs.append(
                    {
                        "source_address": int(block.addr),
                        "target_address": int(successor.addr),
                        "type": "call" if jumpkind == "Ijk_Call" else "jump",
                        "source_function": str(function.name),
                        "target_symbol": (
                            str(target_function.name) if target_function is not None else None
                        ),
                    }
                )
            for instruction in block.capstone.insns:
                if len(instructions) >= instruction_limit:
                    break
                instructions.append(
                    {
                        "address": int(instruction.address),
                        "bytes": bytes(instruction.bytes).hex(),
                        "mnemonic": str(instruction.mnemonic),
                        "operands": str(instruction.op_str),
                        "function_name": str(function.name),
                    }
                )
            if len(instructions) >= instruction_limit:
                break
    symbolic_facts = [
        _symbolically_explore(project, address, step_limit, state_limit) for address in targets
    ]
    document = {
        "functions": functions,
        "instructions": instructions,
        "basic_blocks": basic_blocks,
        "xrefs": xrefs,
        "pseudocode": [],
        "symbolic_facts": symbolic_facts,
        "imports": [],
    }
    output.write_text(json.dumps(document, separators=(",", ":")), encoding="utf-8")


def _symbolically_explore(
    project: Any,
    function_address: int,
    step_limit: int,
    state_limit: int,
) -> dict[str, Any]:
    try:
        state = project.factory.blank_state(addr=function_address)
        manager = project.factory.simulation_manager(state)
        reached: set[int] = set()
        explored_states = 0
        unconstrained_states = 0
        truncated = False
        completed_steps = 0
        for step in range(1, step_limit + 1):
            completed_steps = step
            active = list(manager.active)
            if not active:
                break
            reached.update(int(item.addr) for item in active[:state_limit])
            explored_states += min(len(active), state_limit)
            if len(active) > state_limit:
                manager.stashes["active"] = active[:state_limit]
                truncated = True
            manager.step()
            unconstrained_states += len(manager.unconstrained)
            manager.drop(stash="unconstrained")
        still_active = bool(manager.active)
        status = "partial" if truncated or still_active else "completed"
        reason = "state_or_step_limit" if status == "partial" else None
        return {
            "function_address": function_address,
            "status": status,
            "steps": completed_steps,
            "explored_states": explored_states,
            "reached_addresses": sorted(reached),
            "unconstrained_states": unconstrained_states,
            "reason": reason,
        }
    except Exception as error:  # The isolated helper records per-target failures.
        return {
            "function_address": function_address,
            "status": "failed",
            "steps": 0,
            "explored_states": 0,
            "reached_addresses": [],
            "unconstrained_states": 0,
            "reason": type(error).__name__,
        }


if __name__ == "__main__":
    main()
