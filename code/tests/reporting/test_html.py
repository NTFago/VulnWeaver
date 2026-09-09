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


def test_build_html_counts_proof_runs_per_finding() -> None:
    from typing import cast

    from vulnweaver_contracts import Finding, Poc
    from vulnweaver_reporting.html import build_html

    finding = cast(
        Finding,
        {
            "schema_version": "1.0.0",
            "id": "finding:r1",
            "task_id": "task:r",
            "category": "static_only",
            "cwe_id": "CWE-95",
            "title": "Unsafe eval",
            "severity": "high",
            "confidence": 0.7,
            "location": {
                "artifact_version_id": "artifact-version:r",
                "path": "src/app.py",
                "start_line": 2,
                "start_column": 1,
                "end_line": 2,
                "end_column": 10,
            },
            "dataflow": [],
            "status": "confirmed",
            "evidence_ids": [],
            "review_ids": [],
            "poc_ids": [],
            "fix_suggestion": "Avoid eval",
            "created_at": "2026-09-10T08:00:00Z",
        },
    )
    poc = cast(
        Poc,
        {
            "schema_version": "1.0.0",
            "id": "poc:r1",
            "finding_id": "finding:r1",
            "kind": "proof_of_concept",
            "status": "completed",
            "result": "exploitable",
            "script_ref": "cas://sha256/" + "b" * 64,
            "run_log_ref": None,
            "image_digest": "sha256:" + "a" * 64,
            "permission_mode": "request_permission",
            "resource_budget": {
                "max_model_tokens": 0,
                "cpu_millis": 1000,
                "memory_bytes": 1048576,
                "disk_bytes": 1048576,
                "max_tool_concurrency": 1,
                "max_dynamic_runs": 1,
                "timeout_seconds": 30,
            },
            "created_at": "2026-09-10T08:00:00Z",
        },
    )

    html = build_html([finding], [poc])
    assert "<b>Proof runs:</b> 1" in html
    assert build_html([finding]) .count("Proof runs:</b> 0") == 1
