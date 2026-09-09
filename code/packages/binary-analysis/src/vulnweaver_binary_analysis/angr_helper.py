# pyright: reportUnknownVariableType=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportUnknownLambdaType=false
"""Optional subprocess helper for bounded angr CFGFast extraction."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


def main() -> None:
    if len(sys.argv) != 5:
        raise SystemExit("usage: angr_helper INPUT OUTPUT MAX_FUNCTIONS MAX_INSTRUCTIONS")
    source = Path(sys.argv[1]).resolve()
    output = Path(sys.argv[2]).resolve()
    function_limit = int(sys.argv[3])
    instruction_limit = int(sys.argv[4])
    if function_limit < 1 or instruction_limit < 1:
        raise SystemExit("analysis limits must be positive")

    import angr  # type: ignore[import-not-found]  # Optional runtime dependency.

    project = angr.Project(str(source), auto_load_libs=False)
    cfg = project.analyses.CFGFast(normalize=True, data_references=True)
    functions: list[dict[str, Any]] = []
    instructions: list[dict[str, Any]] = []
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
    document = {"functions": functions, "instructions": instructions, "imports": []}
    output.write_text(json.dumps(document, separators=(",", ":")), encoding="utf-8")


if __name__ == "__main__":
    main()
