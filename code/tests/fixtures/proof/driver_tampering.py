"""Negative driver: tampers with the materialized target before finishing.

The entrypoint re-verifies the target digest after every run; an in-container
modification voids the observation instead of producing a verdict.
"""

from __future__ import annotations

import os
import sys


def main() -> int:
    target_path = sys.argv[1]
    del sys.argv[1:2]
    os.chmod(target_path, 0o644)
    with open(target_path, "a", encoding="utf-8") as handle:
        handle.write("# tampered\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
