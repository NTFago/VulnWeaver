"""HTML source for deterministic PDF rendering."""

from __future__ import annotations

from collections.abc import Sequence
from html import escape

from vulnweaver_contracts import Evidence, Finding, Poc


def _poc_counts(findings: Sequence[Finding], pocs: Sequence[Poc]) -> dict[str, int]:
    counts: dict[str, int] = {finding["id"]: 0 for finding in findings}
    for poc in pocs:
        if poc["finding_id"] in counts:
            counts[poc["finding_id"]] += 1
    return counts


def build_html(
    findings: Sequence[Finding],
    pocs: Sequence[Poc] = (),
    evidence: dict[str, list[Evidence]] | None = None,
) -> str:
    """Build a self-contained, escaped HTML report suitable for a PDF engine."""
    poc_counts = _poc_counts(findings, pocs)
    pocs_by_finding: dict[str, list[Poc]] = {}
    for poc in pocs:
        pocs_by_finding.setdefault(poc["finding_id"], []).append(poc)
    items: list[str] = []
    for finding in findings:
        finding_evidence = (evidence or {}).get(finding["id"], [])
        location = finding["location"]
        address = location.get("address")
        location_text = f"0x{address:x}" if isinstance(address, int) else (
            f"{location.get('path', 'unknown')}:{location.get('line', 1)}"
        )
        severity = escape(str(getattr(finding["severity"], "value", finding["severity"])))
        status = escape(str(getattr(finding["status"], "value", finding["status"])))
        items.append(
            "<article>"
            f"<h2>{escape(finding['title'][:256])}</h2>"
            f"<p><b>ID:</b> <code>{escape(finding['id'])}</code> "
            f"<b>CWE:</b> <code>{escape(finding['cwe_id'])}</code></p>"
            f"<p><b>Location:</b> <code>{escape(str(location_text))}</code></p>"
            f"<p><b>Severity:</b> <code>{severity}</code> "
            f"<b>Status:</b> <code>{status}</code></p>"
            f"<p><b>Evidence references:</b> "
            f"{escape(', '.join(finding['evidence_ids']) or 'none')}<br/>"
            f"<b>Review references:</b> {escape(', '.join(finding['review_ids']) or 'none')}</p>"
            f"<p><b>Proof runs:</b> {poc_counts.get(finding['id'], 0)}</p>"
            + "".join(
                f"<p><b>Proof {escape(poc['id'])}:</b> "
                f"{escape(str(getattr(poc['status'], 'value', poc['status'])))} / "
                f"{escape(str(getattr(poc['result'], 'value', poc['result'])))}</p>"
                for poc in pocs_by_finding.get(finding["id"], [])
            )
            + "".join(
                f"<p><b>Evidence {escape(item['id'])}:</b> "
                f"{escape(str(getattr(item['type'], 'value', item['type'])))}; "
                f"artifact <code>{escape(item['artifact_ref'])}</code>; "
                f"digest <code>{escape(item['digest'])}</code></p>"
                for item in finding_evidence
            )
            + f"<p>{escape(finding['fix_suggestion'][:4096])}</p>"
            "</article>"
        )
    body = "".join(items) or "<p>No findings were reported.</p>"
    return (
        '<!doctype html><html><head><meta charset="utf-8">'
        "<title>VulnWeaver Report</title>"
        "<style>body{font-family:sans-serif;margin:2rem}article{page-break-inside:avoid}"
        "code{font-family:monospace}</style></head>"
        f"<body><h1>VulnWeaver Report</h1>{body}</body></html>"
    )
