from __future__ import annotations

from typing import cast

from vulnweaver_contracts import Finding
from vulnweaver_reporting import build_markdown


def test_markdown_report_is_clear_for_no_findings() -> None:
    assert "No findings" in build_markdown([])


def test_markdown_report_references_evidence_without_embedding_logs() -> None:
    finding = cast(
        Finding,
        {
            "schema_version": "1.0.0", "id": "finding:1", "task_id": "task:1",
            "category": "injection", "cwe_id": "CWE-078", "title": "Injection",
            "severity": "high", "confidence": 0.9,
            "location": {"path": "main.py", "line": 3}, "dataflow": [],
            "status": "confirmed", "evidence_ids": ["evidence:1"],
            "review_ids": ["review:1"], "poc_ids": [], "fix_suggestion": "Fix it",
            "created_at": "2026-01-01T00:00:00+00:00",
        },
    )
    report = build_markdown([finding])
    assert "finding:1" in report
    assert "evidence:1" not in report
    assert "1 referenced artifact" in report
