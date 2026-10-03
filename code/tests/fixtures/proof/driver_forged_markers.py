"""Negative driver: self-reported markers plus a driver-only crash.

Prints an untrusted ``POC_MARKERS`` success claim and then crashes in its own
frames (only on the crafted input, so the control run stays clean). The
entrypoint records the claim but the verdict may only come from a
target-attributed crash, so this run must be rejected.
"""

from __future__ import annotations

import sys


def main() -> int:
    input_path = sys.argv[2]
    with open(input_path, encoding="utf-8") as handle:
        deep = handle.read(4096).count("[") > 100
    print('POC_MARKERS: {"sink_reached": true, "source": "request", "sink": "eval"}')
    if deep:
        raise RuntimeError("driver self crash without the target")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
