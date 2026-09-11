"""Adversarial checks for report facts and printable code excerpts."""

import pytest
from vulnweaver_contracts import FindingStatus, Review, SchemaVersion
from vulnweaver_reporting import build_html, build_markdown
from vulnweaver_reporting.context import CodeExcerpt, ReportContext
from vulnweaver_reporting.excerpts import bounded_excerpt

from tests.reporting.test_markdown import make_evidence, make_finding


def test_false_positive_does_not_raise_confirmed_risk() -> None:
    report = build_markdown([make_finding(status="false_positive", severity="critical")])
    assert "总体风险等级评估为严重" not in report
    assert "没有已确认漏洞" in report
    assert "全部已排除为误报" in report
    assert "最高严重等级：严重" not in report


def test_candidate_is_not_a_confirmed_high_risk() -> None:
    report = build_markdown([make_finding(status="unverifiable", severity="high")])
    assert "待确认" in report
    assert "总体风险等级评估为高" not in report


def test_strong_contradicting_evidence_does_not_remove_warning() -> None:
    report = build_markdown(
        [make_finding(status="candidate")],
        evidence={"finding:1": [make_evidence()]},
        context=ReportContext(evidence_relations={"finding:1": {"evidence:1": "contradicts"}}),
    )
    assert "推测性内容" in report
    assert "反驳" in report


def test_historical_placeholder_has_actionable_chinese_fallback() -> None:
    report = build_markdown(
        [make_finding(fix_suggestion="Address the audited pattern associated with CWE-78.")]
    )
    assert "Address the audited pattern" not in report
    assert "通用建议" in report
    assert "参数化" in report


def test_code_is_escaped_and_its_source_is_preserved_in_both_formats() -> None:
    ctx = ReportContext(
        excerpts={
            "finding:1": CodeExcerpt(
                text='value = "<script>alert(1)</script>"\n```\nreturn value',
                label="原始源码",
                source="artifact-version:fixed · app.py:12",
                first_line=12,
                truncated=True,
            )
        }
    )
    html = build_html([make_finding()], context=ctx)
    markdown = build_markdown([make_finding()], context=ctx)
    assert "<script>" not in html
    assert "&lt;script&gt;" in html
    assert "artifact-version:fixed" in html and "artifact-version:fixed" in markdown
    assert "截断" in html and "截断" in markdown
    assert "````" in markdown
    assert "counter(page)" in html


def test_empty_partial_report_does_not_claim_clean_scan() -> None:
    report = build_markdown(
        [], context=ReportContext(task_result="partial", job_failures=["反编译失败：tool.timeout"])
    )
    assert "覆盖不完整" in report
    assert "反编译失败" in report
    assert "低：本次任务未发现漏洞" not in report


def test_impact_is_marked_as_category_guidance_even_with_strong_evidence() -> None:
    report = build_markdown([make_finding()], evidence={"finding:1": [make_evidence()]})
    assert "类别风险说明，不代表本次已验证影响" in report


@pytest.mark.parametrize("status", ["created", "analyzing", "reporting"])
def test_unsettled_empty_task_has_no_clean_risk_conclusion(status: str) -> None:
    report = build_markdown([], context=ReportContext(task_status=status, task_result=None))
    assert "覆盖不完整" in report
    assert "低：本次任务未发现漏洞" not in report


@pytest.mark.parametrize(
    "source",
    ['password = "private-value"', '{"api_key": "private-value"}', 'token = "private-value'],
)
def test_excerpt_redacts_common_assignments_even_when_truncated(source: str) -> None:
    excerpt = bounded_excerpt(
        CodeExcerpt(
            text=source, label="原始源码", source="version:fixed", first_line=7, truncated=False
        )
    )
    assert "private-value" not in excerpt["text"]
    assert "已脱敏" in excerpt["text"] and "已脱敏" in excerpt["label"]
    assert excerpt["first_line"] == 7


def test_excerpt_enforces_line_and_utf8_byte_budgets() -> None:
    excerpt = bounded_excerpt(
        CodeExcerpt(
            text=("源" * 512 + "\n") * 100,
            label="源码",
            source="version:fixed",
            first_line=1,
            truncated=False,
        )
    )
    assert len(excerpt["text"].splitlines()) <= 80
    assert len(excerpt["text"].encode()) <= 16 * 1024
    assert excerpt["truncated"]


def test_markdown_title_cannot_inject_html_or_external_images() -> None:
    report = build_markdown(
        [make_finding(title='<img src="file:///etc/passwd"> ![x](https://invalid.test/a)')]
    )
    assert "<img" not in report
    assert "&lt;img" in report
    assert "![x]" not in report


def test_evidence_index_links_and_labels_match_the_source_records() -> None:
    evidence = {"finding:1": [make_evidence()]}
    html = build_html([make_finding()], evidence=evidence)
    markdown = build_markdown([make_finding()], evidence=evidence)
    assert 'href="#evidence-finding:1"' in html
    assert 'id="evidence-finding:1"' in html
    assert "E01 · evidence:1" in html and "E01 · evidence:1" in markdown


def test_missing_evidence_does_not_invent_a_model_source() -> None:
    report = build_markdown([make_finding(status="candidate")])
    assert "缺少已解析的支持证据" in report
    assert "关联证据均为模型推断" not in report


def test_long_report_keeps_the_full_remediation_and_review() -> None:
    finding = make_finding(fix_suggestion="修复说明。" * 1200 + "建议末尾标记")
    review = Review(
        schema_version=SchemaVersion.VALUE_1_0_0,
        id="review:long",
        finding_id="finding:1",
        outcome=FindingStatus.CANDIDATE,
        rationale="复核说明。" * 1000 + "复核末尾标记",
        model="test-model",
        supersedes_review_id=None,
        created_at="2026-09-11T00:00:00Z",
    )
    context = ReportContext(reviews={"finding:1": [review]})
    for report in (
        build_html([finding], context=context),
        build_markdown([finding], context=context),
    ):
        assert "建议末尾标记" in report
        assert "复核末尾标记" in report
