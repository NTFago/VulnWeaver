from __future__ import annotations

from pathlib import Path
from typing import cast

from vulnweaver_contracts import Finding
from vulnweaver_reporting import build_html, render_pdf


def test_html_escapes_finding_text() -> None:
    finding = cast(
        Finding,
        {
            "schema_version": "1.0.0",
            "id": "finding:1",
            "task_id": "task:1",
            "category": "injection",
            "cwe_id": "CWE-078",
            "title": "<script>x</script>",
            "severity": "high",
            "confidence": 0.9,
            "location": {"path": "a&b.py", "line": 2},
            "dataflow": [],
            "status": "candidate",
            "evidence_ids": [],
            "review_ids": [],
            "poc_ids": [],
            "fix_suggestion": "<fix>",
            "created_at": "2026-01-01T00:00:00+00:00",
        },
    )
    html = build_html([finding])
    assert "<script>" not in html
    assert "&lt;script&gt;" in html
    assert "a&amp;b.py" in html


def test_pdf_renderer_writes_a_pdf_document(tmp_path: Path) -> None:
    output = render_pdf([], tmp_path / "report.pdf")
    assert output.read_bytes().startswith(b"%PDF-")
