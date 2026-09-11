"""Tests for the Chinese Markdown audit report rendering."""

from __future__ import annotations

from typing import cast

from vulnweaver_contracts import Evidence, Finding, Poc, Review
from vulnweaver_reporting import build_markdown
from vulnweaver_reporting.chinese import (
    MODEL_INFERRED_MARK,
    SPECULATIVE_MARK,
)
from vulnweaver_reporting.context import ReportContext, SampleSummary


def make_finding(**overrides: object) -> Finding:
    """Return a minimal canonical Finding with optional field overrides."""
    base: dict[str, object] = {
        "schema_version": "1.0.0",
        "id": "finding:1",
        "task_id": "task:1",
        "category": "injection",
        "cwe_id": "CWE-078",
        "title": "Injection",
        "severity": "high",
        "confidence": 0.9,
        "location": {"path": "main.py", "line": 3},
        "dataflow": [],
        "call_path": [],
        "status": "confirmed",
        "evidence_ids": [],
        "review_ids": [],
        "poc_ids": [],
        "fix_suggestion": "Fix it",
        "created_at": "2026-01-01T00:00:00+00:00",
    }
    base.update(overrides)
    return cast(Finding, base)


def make_evidence(**overrides: object) -> Evidence:
    """Return a minimal canonical Evidence record with optional overrides."""
    base: dict[str, object] = {
        "schema_version": "1.0.0",
        "id": "evidence:1",
        "type": "tool_output",
        "strength": "strong",
        "artifact_ref": "cas://minimized-input",
        "digest": "sha256:" + "a" * 64,
        "tool": {"name": "semgrep", "version": "1.130.0", "image_digest": None},
        "input_ref": "cas://input",
        "command_hash": None,
        "exit_code": None,
        "stdout_ref": None,
        "stderr_ref": None,
        "replay_recipe": {},
        "created_at": "2026-01-01T00:00:00Z",
    }
    base.update(overrides)
    return cast(Evidence, base)


def make_poc(**overrides: object) -> Poc:
    """Return a minimal canonical Poc record with optional overrides."""
    base: dict[str, object] = {
        "schema_version": "1.0.0",
        "id": "poc:1",
        "finding_id": "finding:1",
        "kind": "proof_of_concept",
        "status": "completed",
        "result": "exploitable",
        "script_ref": "cas://script",
        "run_log_ref": "cas://run-log",
        "image_digest": "sha256:" + "b" * 64,
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
        "created_at": "2026-01-01T00:00:00Z",
    }
    base.update(overrides)
    return cast(Poc, base)


def make_context(**overrides: object) -> ReportContext:
    """Return a report context covering samples, task metadata, and reviews."""
    base: dict[str, object] = {
        "task_id": "task:demo",
        "task_created_at": "2026-01-01T00:00:00+00:00",
        "task_updated_at": "2026-01-02T00:00:00+00:00",
        "task_result": "partial",
        "failure_code": "binary.partial_analysis",
        "failure_kind": "tool",
        "failure_message": "Ghidra decompile timed out",
        "produced_by": "vulnweaver-report@1.0.0",
        "samples": [
            SampleSummary(
                name="demo.elf",
                digest="sha256:" + "c" * 64,
                kind="elf",
            )
        ],
        "reviews": {},
    }
    base.update(overrides)
    return cast(ReportContext, base)


def test_markdown_report_is_complete_for_no_findings() -> None:
    report = build_markdown([])
    assert "本次任务未报告任何漏洞发现" in report
    for section in ("执行摘要", "风险统计", "漏洞列表", "附录"):
        assert section in report
    assert "严重等级分布" in report
    assert "确认状态分布" in report
    assert "0（未发现漏洞）" in report


def test_markdown_summary_renders_sample_and_task_metadata() -> None:
    finding = make_finding()
    report = build_markdown([finding], context=make_context())
    assert "demo.elf" in report
    assert "sha256:" + "c" * 64 in report
    assert "ELF 二进制" in report
    assert "task:demo" in report
    assert "部分成功（partial）" in report
    assert "vulnweaver-report@1.0.0" in report
    assert "发现漏洞总数 | 1（最高严重等级：高危（high））" in report


def test_markdown_summary_renders_failure_and_limitations() -> None:
    report = build_markdown([make_finding()], context=make_context())
    assert "主要限制" in report
    assert "任务记录到结构化失败" in report
    assert "binary.partial_analysis" in report
    assert "附录" in report
    assert "失败原因汇总" in report


def test_markdown_without_context_shows_missing_placeholders() -> None:
    report = build_markdown([make_finding()])
    assert "未提供" in report


def test_markdown_task_result_pending_when_result_not_yet_settled() -> None:
    context = make_context(task_result=None)
    report = build_markdown([make_finding()], context=context)  # type: ignore[arg-type]
    assert "待最终归类" in report


def test_markdown_statistics_cover_every_severity_and_status_row() -> None:
    report = build_markdown([make_finding(severity="high", status="confirmed")])
    for label in (
        "严重（critical） | 0",
        "高危（high） | 1",
        "中危（medium） | 0",
        "低危（low） | 0",
        "提示（info） | 0",
        "已确认（confirmed） | 1",
        "候选（candidate） | 0",
        "误报（false_positive） | 0",
        "争议（disputed） | 0",
        "不可验证（unverifiable） | 0",
    ):
        assert label in report


def test_markdown_finding_heading_keeps_title_and_cwe_verbatim() -> None:
    report = build_markdown([make_finding()])
    assert "### 3.1【高危 · 注入】Injection（CWE-078）" in report
    assert "| 严重等级 | 高危（high） |" in report
    assert "| 可信度 | 0.90（高可信） |" in report
    assert "| 状态 | 已确认（confirmed） |" in report


def test_markdown_renders_canonical_binary_location() -> None:
    finding = make_finding(
        id="finding:binary",
        category="static_only",
        cwe_id="CWE-22",
        title="Path issue",
        severity="medium",
        confidence=0.4,
        status="candidate",
        location={
            "artifact_version_id": "artifact-version:1",
            "virtual_address": 0x401000,
            "file_offset": 0,
        },
    )
    report = build_markdown([finding])
    assert "0x401000" in report
    assert "二进制地址" in report


def test_markdown_binary_location_appends_target_function_from_call_path() -> None:
    finding = make_finding(
        location={
            "artifact_version_id": "artifact-version:1",
            "virtual_address": 0x401000,
        },
        call_path=[
            {
                "relation": "target",
                "function_name": "handler",
                "path": None,
                "line": None,
                "address": 0x401000,
            }
        ],
    )
    report = build_markdown([finding])
    assert "0x401000（二进制地址，函数 handler）" in report


def test_markdown_report_references_evidence_without_embedding_logs() -> None:
    finding = make_finding(
        location={
            "artifact_version_id": "artifact-version:1",
            "path": "main.py",
            "start_line": 3,
            "start_column": 1,
            "end_line": 4,
            "end_column": 4,
        },
        evidence_ids=["evidence:1"],
        review_ids=["review:1"],
    )
    evidence = {"finding:1": [make_evidence()]}
    report = build_markdown([finding], evidence=evidence)  # type: ignore[arg-type]
    assert "finding:1" in report
    assert "main.py:3-4" in report
    assert "evidence:1" in report
    assert "review:1" in report
    assert "原始工具输出与运行日志以不可变工件引用保存" in report
    assert "semgrep@1.130.0" in report
    assert "工具输出（tool_output）" in report
    assert "强证据" in report


def test_markdown_renders_evidence_artifact_and_crash_summary() -> None:
    evidence = {
        "finding:1": [
            make_evidence(
                id="evidence:crash",
                type="crash_record",
                tool=None,
                exit_code=11,
                replay_recipe={"stack_hash": "sha256:" + "b" * 64},
            )
        ]
    }
    report = build_markdown([make_finding()], evidence=evidence)  # type: ignore[arg-type]
    assert "cas://minimized-input" in report
    assert "崩溃栈哈希" in report
    assert "工具退出码：11" in report
    assert "未提供" in report


def test_markdown_renders_the_projected_call_path_with_chinese_relations() -> None:
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
                "relation": "caller",
                "function_name": "main",
                "path": "src/main.c",
                "line": 3,
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
        dataflow=[
            {"pair_node_id": "node:1", "label": "input", "order": 1},
            {"pair_node_id": "node:2", "label": "sink", "order": 2},
        ],
    )

    report = build_markdown([finding])

    assert "#### 触发条件与调用路径" in report
    assert "漏洞目标函数 handler（src/app.c:10）" in report
    assert "调用方 main（src/main.c:3）" in report
    assert "被调用方 win_copy（0x401000）" in report
    assert "数据流：input → sink" in report


def test_markdown_states_the_missing_call_path_explicitly() -> None:
    report = build_markdown([make_finding()])
    assert "静态分析未能固化调用路径。" in report


def test_markdown_marks_model_only_findings_for_human_confirmation() -> None:
    finding = make_finding(status="candidate")
    evidence = {
        "finding:1": [
            make_evidence(type="model_explanation", strength="contextual", tool=None)
        ]
    }
    report = build_markdown([finding], evidence=evidence)  # type: ignore[arg-type]
    assert MODEL_INFERRED_MARK in report
    assert SPECULATIVE_MARK in report
    assert "#### 待人工确认项" in report
    assert "当前状态为候选（candidate）" in report
    assert "关联证据均为模型推断说明" in report
    assert "模型推断说明（model_explanation）" in report


def test_markdown_confirmed_finding_with_strong_evidence_has_no_speculation() -> None:
    finding = make_finding(status="confirmed")
    evidence = {"finding:1": [make_evidence()]}
    report = build_markdown([finding], evidence=evidence)  # type: ignore[arg-type]
    assert "推测性内容" not in report
    assert MODEL_INFERRED_MARK not in report
    assert "待人工确认项" in report
    assert "- 无。" in report


def test_markdown_limits_findings_by_severity_order() -> None:
    report = build_markdown(
        [
            make_finding(id="finding:low", severity="low"),
            make_finding(id="finding:critical", severity="critical", cwe_id="CWE-120"),
        ]
    )
    assert report.index("3.1【严重") < report.index("3.2【低危")


def test_markdown_uses_generic_remediation_when_suggestion_is_missing() -> None:
    report = build_markdown([make_finding(fix_suggestion="")])
    assert "（通用建议" in report


def test_markdown_renders_poc_verification_status() -> None:
    report = build_markdown([make_finding()], pocs=[make_poc()])
    assert "poc:1" in report
    assert "概念验证（Poc）" in report
    assert "已完成（completed）" in report
    assert "可利用（exploitable）" in report
    assert "运行日志 cas://run-log" in report


def test_markdown_states_when_dynamic_verification_is_absent() -> None:
    report = build_markdown([make_finding()])
    assert "未执行动态验证：该发现没有关联的 Poc 执行记录。" in report


def test_markdown_appendix_lists_review_history() -> None:
    review = cast(
        Review,
        {
            "schema_version": "1.0.0",
            "id": "review:1",
            "finding_id": "finding:1",
            "outcome": "confirmed",
            "rationale": "Evidence reproduces.",
            "model": "review-model",
            "supersedes_review_id": None,
            "created_at": "2026-01-02T00:00:00+00:00",
        },
    )
    context = make_context(reviews={"finding:1": [review]})
    report = build_markdown([make_finding()], context=context)
    assert "复核历史" in report
    assert "review:1" in report
    assert "结论 已确认（confirmed）" in report
    assert "Evidence reproduces." in report


def test_markdown_appendix_notes_when_reviews_are_absent() -> None:
    report = build_markdown([make_finding()], context=make_context())
    assert "本次任务没有已登记的复核记录。" in report
