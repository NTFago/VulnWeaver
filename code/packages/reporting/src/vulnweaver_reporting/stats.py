"""Pure aggregation helpers shared by the Markdown and HTML report renderers."""

from __future__ import annotations

from collections.abc import Sequence

from vulnweaver_contracts import Finding, Poc

from vulnweaver_reporting.chinese import (
    FINDING_STATUS_ZH,
    SEVERITY_ORDER,
    SEVERITY_ZH,
    raw_value,
)
from vulnweaver_reporting.locations import binary_address, location_text

#: Every severity and status row the statistics tables must show, even at zero.
SEVERITY_ROWS: tuple[str, ...] = ("critical", "high", "medium", "low", "info")
STATUS_ROWS: tuple[str, ...] = (
    "confirmed",
    "candidate",
    "false_positive",
    "disputed",
    "unverifiable",
)


def group_pocs(pocs: Sequence[Poc]) -> dict[str, list[Poc]]:
    """Group Poc records by their finding identifier."""
    grouped: dict[str, list[Poc]] = {}
    for poc in pocs:
        grouped.setdefault(poc["finding_id"], []).append(poc)
    return grouped


def severity_counts(findings: Sequence[Finding]) -> dict[str, int]:
    """Count findings per severity value, including zero rows."""
    counts = {row: 0 for row in SEVERITY_ROWS}
    for finding in findings:
        value = raw_value(finding["severity"])
        if value in counts:
            counts[value] += 1
    return counts


def status_counts(findings: Sequence[Finding]) -> dict[str, int]:
    """Count findings per review status value, including zero rows."""
    counts = {row: 0 for row in STATUS_ROWS}
    for finding in findings:
        value = raw_value(finding["status"])
        if value in counts:
            counts[value] += 1
    return counts


def highest_severity(findings: Sequence[Finding]) -> str | None:
    """Return the raw value of the most severe finding, or None when empty."""
    ranked = [
        value
        for value in (raw_value(finding["severity"]) for finding in findings)
        if value in SEVERITY_ORDER
    ]
    if not ranked:
        return None
    return min(ranked, key=lambda value: SEVERITY_ORDER[value])


def nonempty_status_summary(findings: Sequence[Finding]) -> list[str]:
    """Return ``中文（raw） × count`` fragments for statuses present in the input."""
    counts = status_counts(findings)
    return [
        f"{label}（{value}）{counts[value]} 个"
        for value, label in ((row, FINDING_STATUS_ZH[row]) for row in STATUS_ROWS)
        if counts[value]
    ]


def location_parts(finding: Finding) -> tuple[str, str, str | None]:
    """Return the bounded location text, its Chinese kind, and a binary function name.

    The function name is only filled for binary locations whose projected call
    path contains an explicit target step, so reports never invent symbols.
    """
    address = binary_address(finding["location"])
    if isinstance(address, int):
        return f"0x{address:x}", "二进制地址", _binary_target_function(finding)
    return location_text(finding["location"]), "源码位置", None


def dataflow_labels(finding: Finding) -> list[str]:
    """Return the recorded dataflow step labels ordered by their projection order."""
    ordered = sorted(finding["dataflow"], key=lambda step: step["order"])
    return [step["label"][:1024] for step in ordered]


def _binary_target_function(finding: Finding) -> str | None:
    for step in finding["call_path"]:
        if raw_value(step["relation"]) != "target":
            continue
        if step["path"] is None:
            return step["function_name"][:2048]
    return None


def severity_label(value: str) -> str:
    """Chinese label for a raw severity value, falling back to the raw text."""
    return SEVERITY_ZH.get(value, value)
