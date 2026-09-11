"""Bounded pseudocode projection for indexed binary functions.

The binary importer stores ``PairFunction.attributes["pseudocode"]`` as the list
of ``BinaryPseudocode`` records produced by the decompiler, while source-derived
functions carry no pseudocode at all. Readers that assumed a plain string
silently produced no code for every binary function, so this module is the one
place that knows the real shape.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import cast

from vulnweaver_contracts import PairFunction, SourceLocation

__all__ = ["pseudocode_text", "source_location_of", "binary_address_of"]

DEFAULT_PSEUDOCODE_CHARS = 16_384


def pseudocode_text(
    function: PairFunction, *, limit: int = DEFAULT_PSEUDOCODE_CHARS
) -> str:
    """Return the function's pseudocode as bounded text, or ``""`` when absent.

    A decompiler may emit several records for one address range (for example a
    flattened function plus its recovered body); they are joined in ascending
    address order so the result is deterministic.
    """

    if limit < 1:
        raise ValueError("pseudocode text limit must be positive")
    raw = function["attributes"].get("pseudocode")
    if isinstance(raw, str):
        return raw.strip()[:limit]
    if not isinstance(raw, list):
        return ""
    records: list[tuple[int, str]] = []
    for item in cast(list[object], raw):
        if not isinstance(item, Mapping):
            continue
        entry = cast(Mapping[str, object], item)
        text = entry.get("text")
        if not isinstance(text, str) or not text.strip():
            continue
        address = entry.get("address")
        records.append((address if isinstance(address, int) else 0, text.strip()))
    records.sort(key=lambda item: item[0])
    return "\n\n".join(text for _, text in records)[:limit]


def source_location_of(function: PairFunction) -> SourceLocation | None:
    location = function["source_location"]
    return location if location is not None else None


def binary_address_of(function: PairFunction) -> int | None:
    location = function["binary_location"]
    if location is None:
        return None
    return location["virtual_address"]
