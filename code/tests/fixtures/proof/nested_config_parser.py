"""Teaching sample: nested-section config parser with unbounded recursion.

Self-authored sample (CWE-674 pattern) for target-bound verification
acceptance. The fault is real: ``_parse_block`` recurses once per ``[`` with
no depth bound, so a deeply nested input raises RecursionError inside this
file's frames. The crash must come from this original file — a driver that
reimplements the recursion proves nothing about the sample. Registered in
tests/fixtures/README.md; trigger input ``[`` * N, control input ``[a]b=c``.
"""

from __future__ import annotations


def parse(text: str) -> dict[str, object]:
    blocks, _ = _parse_block(text, 0)
    return blocks


def _parse_block(text: str, position: int) -> tuple[dict[str, object], int]:
    result: dict[str, object] = {}
    while position < len(text):
        char = text[position]
        if char == "[":
            inner, position = _parse_block(text, position + 1)
            nested = result.setdefault("blocks", [])
            nested.append(inner)
        elif char == "]":
            return result, position + 1
        else:
            position += 1
    return result, position
