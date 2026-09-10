"""Conservative, provenance-preserving control-flow readability recovery.

The original decompiler output is evidence and is never changed.  This module
creates a separately labelled view that makes dispatcher labels and transfers
explicit for human review.  It intentionally does not claim semantic recovery:
an optional model pass may improve names and comments, while this deterministic
baseline remains available when no model is configured.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence

from vulnweaver_contracts import BinaryPseudocode

from vulnweaver_binary_analysis.obfuscation import ObfuscationAssessment

_LABEL = re.compile(r"(?m)^\s*(?:LAB|label)_([0-9A-Fa-f]+):")
_GOTO = re.compile(r"\bgoto\s+(?:LAB|label)_([0-9A-Fa-f]+)\s*;")


def recover_readable_pseudocode(
    pseudocode: Sequence[BinaryPseudocode],
    assessments: Sequence[ObfuscationAssessment],
    *,
    max_chars: int,
) -> tuple[BinaryPseudocode, ...]:
    """Produce a bounded, separately identified review view for each function."""
    if max_chars < 1:
        raise ValueError("max_chars must be positive")
    assessment_by_name = {item.function_name: item for item in assessments}
    recovered: list[BinaryPseudocode] = []
    for item in pseudocode:
        assessment = assessment_by_name.get(item["function_name"])
        recovered.append(
            BinaryPseudocode(
                function_name=item["function_name"],
                address=item["address"],
                text=_recover_text(item["text"], assessment, max_chars),
                tool_name="vulnweaver-readable",
            )
        )
    return tuple(recovered)


def validate_model_readable_pseudocode(
    raw: Sequence[BinaryPseudocode],
    candidates: Sequence[Mapping[str, object]],
    *,
    max_chars: int,
) -> tuple[BinaryPseudocode, ...]:
    """Accept only bounded model views anchored to an original function address."""
    raw_by_address = {item["address"]: item for item in raw}
    accepted: list[BinaryPseudocode] = []
    for candidate in candidates:
        address = candidate.get("address")
        text = candidate.get("text")
        if isinstance(address, bool) or not isinstance(address, int) or not isinstance(text, str):
            continue
        source = raw_by_address.get(address)
        if source is None or not text.strip() or len(text) > max_chars:
            continue
        name = candidate.get("function_name")
        function_name = (
            name[:4096] if isinstance(name, str) and name.strip() else source["function_name"]
        )
        accepted.append(
            BinaryPseudocode(
                function_name=function_name,
                address=address,
                text=text,
                tool_name="model-readable",
            )
        )
    return tuple(sorted(accepted, key=lambda item: item["address"]))


def _recover_text(
    text: str, assessment: ObfuscationAssessment | None, max_chars: int
) -> str:
    normalized = _LABEL.sub(lambda match: f"/* block 0x{match.group(1)} */", text)
    normalized = _GOTO.sub(
        lambda match: f"/* control transfer to block 0x{match.group(1)} */", normalized
    )
    if assessment is not None and assessment.flattened:
        prefix = (
            "/* VulnWeaver readable view: suspected flattened control flow. "
            f"{assessment.reason}. Labels and dispatcher transfers are made explicit; "
            "consult the original decompiler output for evidence. */\n"
        )
        normalized = prefix + normalized
    return normalized[:max_chars]
