"""Tests for the Chinese HTML report rendering and the PDF pipeline."""

from __future__ import annotations

from pathlib import Path

from vulnweaver_reporting import build_html, render_pdf
from vulnweaver_reporting.chinese import MODEL_INFERRED_MARK, SPECULATIVE_MARK

from tests.reporting.test_markdown import make_context, make_evidence, make_finding, make_poc


def test_html_declares_chinese_document_and_font_stack() -> None:
    html = build_html([make_finding()])
    assert 'lang="zh-CN"' in html
    assert "Noto Sans CJK SC" in html
    assert "执行摘要" in html
    assert "风险统计" in html
    assert "漏洞列表" in html
    assert "附录" in html


def test_html_escapes_finding_text() -> None:
    finding = make_finding(
        title="<script>x</script>",
        location={"path": "a&b.py", "line": 2},
        fix_suggestion="<fix>",
    )
    html = build_html([finding])
    assert "<script>" not in html
    assert "&lt;script&gt;" in html
    assert "a&amp;b.py" in html
    assert "&lt;fix&gt;" in html


def test_pdf_renderer_writes_a_pdf_document(tmp_path: Path) -> None:
    output = render_pdf([], tmp_path / "report.pdf")
    assert output.read_bytes().startswith(b"%PDF-")


def test_pdf_renderer_includes_context_metadata(tmp_path: Path) -> None:
    output = render_pdf(
        [make_finding()],
        tmp_path / "report.pdf",
        context=make_context(),
    )
    assert output.stat().st_size > 0


def test_html_renders_poc_verification_per_finding() -> None:
    finding = make_finding(id="finding:r1", cwe_id="CWE-95", title="Unsafe eval")
    poc = make_poc(id="poc:r1", finding_id="finding:r1")
    html = build_html([finding], [poc])
    assert "poc:r1" in html
    assert "可利用（exploitable）" in html
    assert "运行日志 cas://run-log" in html


def test_html_states_missing_dynamic_verification() -> None:
    html = build_html([make_finding()])
    assert "未执行动态验证：该发现没有关联的 Poc 执行记录。" in html


def test_html_renders_the_projected_call_path_with_chinese_relations() -> None:
    finding = make_finding(
        id="finding:call-path",
        category="memory_corruption",
        cwe_id="CWE-120",
        title="Overflow",
        severity="critical",
        confidence=0.8,
        location={"path": "src/app.c", "line": 10},
        call_path=[
            {
                "relation": "target",
                "function_name": "handler",
                "path": "src/app.c",
                "line": 10,
                "address": None,
            },
            {
                "relation": "callee",
                "function_name": "win_copy",
                "path": None,
                "line": None,
                "address": 0x401000,
            },
        ],
    )

    html = build_html([finding])

    assert "触发条件与调用路径" in html
    assert "漏洞目标函数 handler（src/app.c:10）" in html
    assert "被调用方 win_copy（0x401000）" in html


def test_html_marks_model_only_findings_as_speculative() -> None:
    finding = make_finding(status="candidate")
    evidence = {
        "finding:1": [
            make_evidence(type="model_explanation", strength="contextual", tool=None)
        ]
    }
    html = build_html([finding], evidence=evidence)  # type: ignore[arg-type]
    assert "speculative" in html
    assert MODEL_INFERRED_MARK in html
    assert SPECULATIVE_MARK in html
    assert "待人工确认项" in html


def test_html_renders_sample_metadata_from_context() -> None:
    html = build_html([make_finding()], context=make_context())
    assert "demo.elf" in html
    assert "部分成功（partial）" in html
    assert "失败原因汇总" in html


def test_html_statistics_tables_cover_every_row() -> None:
    html = build_html([make_finding(severity="high", status="confirmed")])
    for label in (
        "严重（critical）",
        "高危（high）",
        "已确认（confirmed）",
        "不可验证（unverifiable）",
    ):
        assert label in html
