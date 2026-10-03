"""Positive driver: load and invoke the original target exactly as provided.

The materialized target has no ``.py`` extension (the bundle reserves plain
``target`` for any sample kind), so an explicit source loader is required.
The loader keeps the real file path in stack frames, which is exactly what
the entrypoint's target attribution checks.
"""

from __future__ import annotations

import importlib.util
import sys
from importlib.machinery import SourceFileLoader


def main() -> int:
    target_path = sys.argv[1]
    input_path = sys.argv[2]
    loader = SourceFileLoader("vw_original_target", target_path)
    spec = importlib.util.spec_from_file_location(
        "vw_original_target", target_path, loader=loader
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with open(input_path, encoding="utf-8") as handle:
        module.parse(handle.read())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
