"""Bounded Markdown report rendering."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from vulnweaver_contracts import Evidence, Finding, Poc


def build_markdown(
    findings: Sequence[Finding],
    pocs: Sequence[Poc] = (),
    evidence: dict[str, list[Evidence]] | None = None,
) -> str:
    """Render a reviewable report while keeping raw evidence out of the document."""
    poc_by_finding: dict[str, list[Poc]] = {}
    for poc in pocs:
        poc_by_finding.setdefault(poc["finding_id"], []).append(poc)
    lines = ["# VulnWeaver Report", "", f"Findings: {len(findings)}", ""]
    if not findings:
        return "\n".join(lines + ["No findings were reported.", ""])
    for finding in findings:
        finding_evidence = (evidence or {}).get(finding["id"], [])
        location = finding["location"]
        location_text = _location_text(location)
        lines.extend(
            [
                f"## {finding['title'][:256]}",
                "",
                f"- ID: `{finding['id']}`",
                f"- CWE: `{finding['cwe_id']}`",
                f"- Severity: `{_value(finding['severity'])}`",
                f"- Status: `{_value(finding['status'])}`",
                f"- Confidence: `{finding['confidence']:.2f}`",
                f"- Location: `{location_text}`",
                f"- Evidence: {len(finding['evidence_ids'])} referenced artifact(s)",
                f"- Reviews: {len(finding['review_ids'])}",
                f"- Proof runs: {len(poc_by_finding.get(finding['id'], []))}",
                "",
                "### Remediation",
                "",
                finding["fix_suggestion"][:4096],
                "",
            ]
        )
        call_path = finding["call_path"]
        if call_path:
            lines.extend(["### Call path", ""])
            lines.extend(f"- {_call_path_step(step)}" for step in call_path)
            lines.append("")
        lines.extend(
            [
                "### Evidence chain",
                "",
                f"- Evidence references: "
                f"{', '.join(f'`{item}`' for item in finding['evidence_ids']) or 'none'}",
                f"- Review references: "
                f"{', '.join(f'`{item}`' for item in finding['review_ids']) or 'none'}",
                "",
            ]
        )
        for item in finding_evidence:
            recipe = item["replay_recipe"]
            lines.append(
                f"- `{item['id']}`: `{_value(item['type'])}`, artifact `{item['artifact_ref']}`, "
                f"digest `{item['digest']}`"
            )
            if "stack_hash" in recipe:
                lines.append(f"  - Crash stack: `{recipe['stack_hash']}`")
        for poc in poc_by_finding.get(finding["id"], []):
            lines.append(
                f"- POC `{poc['id']}`: `{_value(poc['status'])}` / "
                f"`{_value(poc['result']) if poc['result'] is not None else 'pending'}`"
            )
        lines.append("")
    lines.extend(
        [
            "### Limitations",
            "",
            "Raw tool output and logs are retained as artifact references.",
            "",
        ]
    )
    return "\n".join(lines)


def _value(value: object) -> str:
    member = getattr(value, "value", value)
    return member if isinstance(member, str) else str(member)


def _call_path_step(step: Mapping[str, object]) -> str:
    relation = _value(step["relation"])
    name = str(step["function_name"])[:2048]
    path = step.get("path")
    line = step.get("line")
    if isinstance(path, str) and path:
        where = f"{path[:4096]}:{line if isinstance(line, int) else 1}"
    else:
        address = step.get("address")
        where = f"0x{address:x}" if isinstance(address, int) else "unknown"
    return f"`{relation}` {name} (`{where}`)"


def _location_text(location: Mapping[str, object]) -> str:
    address = location.get("address")
    if isinstance(address, int):
        return f"0x{address:x}"
    path = location.get("path", "unknown")
    return f"{str(path)[:4096]}:{location.get('line', 1)}"
