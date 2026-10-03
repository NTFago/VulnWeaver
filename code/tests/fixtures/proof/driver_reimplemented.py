"""Negative driver: reimplements the recursion pattern instead of the target.

This is the "wrong target" negative: the crash only happens for the crafted
input (the control run stays clean), but every frame belongs to the driver,
so it cannot evidence a fault in the original sample.
"""

from __future__ import annotations

import sys


def _recursive(position: int) -> int:
    return _recursive(position + 1)


def main() -> int:
    input_path = sys.argv[2]
    with open(input_path, encoding="utf-8") as handle:
        deep = handle.read(4096).count("[") > 100
    if deep:
        return _recursive(0)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
