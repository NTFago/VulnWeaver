"""Negative driver: does nothing, so it proves nothing about the target."""

from __future__ import annotations

import sys


def main() -> int:
    del sys.argv
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
