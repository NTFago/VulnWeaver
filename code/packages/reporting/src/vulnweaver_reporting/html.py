"""HTML source for deterministic PDF rendering."""

from __future__ import annotations

from collections.abc import Sequence
from html import escape

from vulnweaver_contracts import Finding


def build_html(findings: Sequence[Finding]) -> str:
    """Build a self-contained, escaped HTML report suitable for a PDF engine."""
    items: list[str] = []
    for finding in findings:
        location = finding["location"]
        path = escape(str(location.get("path", "unknown")))
        line = location.get("line", 1)
        items.append(
            "<article>"
            f"<h2>{escape(finding['title'][:256])}</h2>"
            f"<p><b>ID:</b> <code>{escape(finding['id'])}</code> "
            f"<b>CWE:</b> <code>{escape(finding['cwe_id'])}</code></p>"
            f"<p><b>Location:</b> <code>{path}:{line}</code></p>"
            f"<p>{escape(finding['fix_suggestion'][:4096])}</p>"
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
