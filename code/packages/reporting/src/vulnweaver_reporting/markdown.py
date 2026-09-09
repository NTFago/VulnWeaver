"""Bounded Markdown report rendering."""

from __future__ import annotations

from collections.abc import Sequence

from vulnweaver_contracts import Finding, Poc


def build_markdown(findings: Sequence[Finding], pocs: Sequence[Poc] = ()) -> str:
    """Render a reviewable report while keeping raw evidence out of the document."""
    poc_by_finding: dict[str, list[Poc]] = {}
    for poc in pocs:
        poc_by_finding.setdefault(poc["finding_id"], []).append(poc)
    lines = ["# VulnWeaver Report", "", f"Findings: {len(findings)}", ""]
    if not findings:
        return "\n".join(lines + ["No findings were reported.", ""])
    for finding in findings:
        location = finding["location"]
        path = location.get("path", "unknown")
        line = location.get("line", 1)
        lines.extend(
            [
                f"## {finding['title'][:256]}",
                "",
                f"- ID: `{finding['id']}`",
                f"- CWE: `{finding['cwe_id']}`",
                f"- Severity: `{_value(finding['severity'])}`",
                f"- Status: `{_value(finding['status'])}`",
                f"- Confidence: `{finding['confidence']:.2f}`",
                f"- Location: `{str(path)[:4096]}:{line}`",
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
