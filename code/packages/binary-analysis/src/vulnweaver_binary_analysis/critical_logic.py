"""Deterministic candidate discovery for security-critical binary functions."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from vulnweaver_contracts import BinaryFunction, BinaryImport, BinaryString


@dataclass(frozen=True, slots=True)
class CriticalLogicCandidate:
    function_name: str
    category: str
    score: float
    evidence: tuple[str, ...]


def discover_critical_logic(
    functions: Sequence[BinaryFunction],
    imports: Sequence[BinaryImport] = (),
    strings: Sequence[BinaryString] = (),
) -> tuple[CriticalLogicCandidate, ...]:
    """Score functions using bounded import/string/name signals.

    Results are candidates for later model confirmation, never confirmed findings.
    """
    signals = {
        "auth": ("auth", "login", "password", "token", "credential"),
        "crypto": ("crypt", "encrypt", "decrypt", "aes", "sha", "hmac"),
        "registration": ("register", "license", "activation", "serial"),
    }
    text = (
        " ".join((item["name"] or "") for item in imports).lower()
        + " "
        + " ".join(item["value"] for item in strings).lower()
    )
    output: list[CriticalLogicCandidate] = []
    for function in functions:
        name = function["name"]
        haystack = f"{name} {text}".lower()
        for category, keywords in signals.items():
            hits = tuple(keyword for keyword in keywords if keyword in haystack)
            if hits:
                score = min(1.0, 0.45 + 0.1 * len(hits))
                output.append(CriticalLogicCandidate(name, category, score, hits[:8]))
    return tuple(sorted(output, key=lambda item: (item.category, item.function_name)))
