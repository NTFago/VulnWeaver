"""Format-neutral report model shared by the Markdown and HTML renderers.

The model holds only facts taken from scan-result fields (findings, Pocs,
evidence, persisted task metadata). Copy strings come from :mod:`chinese`;
missing fields render as ``未提供`` so the document never invents data.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from vulnweaver_contracts import Evidence, Finding, Poc

from vulnweaver_reporting.chinese import (
    CALL_PATH_RELATION_ZH,
    EVIDENCE_STRENGTH_ZH,
    EVIDENCE_TYPE_ZH,
    FINDING_CATEGORY_ZH,
    FINDING_STATUS_ZH,
    LABEL_CATEGORY,
    LABEL_CONFIDENCE,
    LABEL_CONTENT,
    LABEL_COUNT,
    LABEL_CREATED_AT,
    LABEL_EVIDENCE_ARTIFACT,
    LABEL_EVIDENCE_TOOL,
    LABEL_FINDING_ID,
    LABEL_FINDING_TOTAL,
    LABEL_ITEM,
    LABEL_LOCATION,
    LABEL_OVERALL_RISK,
    LABEL_PRODUCED_BY,
    LABEL_SAMPLE,
    LABEL_SEVERITY,
    LABEL_STATUS,
    LABEL_STATUS_SUMMARY,
    LABEL_TASK_ID,
    LABEL_TASK_RESULT,
    LABEL_UPDATED_AT,
    MISSING,
    MODEL_INFERRED_MARK,
    POC_KIND_ZH,
    POC_RESULT_ZH,
    POC_STATUS_ZH,
    REPORT_TITLE,
    SAMPLE_KIND_ZH,
    SECTION_APPENDIX,
    SECTION_DATA_NOTES,
    SECTION_FAILURES,
    SECTION_FINDINGS,
    SECTION_LIMITS,
    SECTION_METADATA,
    SECTION_REVIEWS,
    SECTION_SEVERITY_DISTRIBUTION,
    SECTION_STATS,
    SECTION_STATUS_DISTRIBUTION,
    SECTION_SUMMARY,
    SEVERITY_ZH,
    SPECULATIVE_NOTE,
    SUBSECTION_CONFIRMATION,
    SUBSECTION_EVIDENCE,
    SUBSECTION_FIX,
    SUBSECTION_IMPACT,
    SUBSECTION_TRIGGER,
    SUBSECTION_VERIFICATION,
    TASK_RESULT_DETAIL_ZH,
    TASK_RESULT_ZH,
    TEXT_CRASH_STACK,
    TEXT_DATAFLOW,
    TEXT_EVIDENCE_DIGEST,
    TEXT_EVIDENCE_REFS,
    TEXT_EXIT_CODE,
    TEXT_HIGHEST_SEVERITY,
    TEXT_LIMIT_BLOCKED_POCS,
    TEXT_LIMIT_FAILURE,
    TEXT_LIMIT_MODEL_ONLY,
    TEXT_NO_BLOCKERS,
    TEXT_NO_CALL_PATH,
    TEXT_NO_CONFIRMATION,
    TEXT_NO_DYNAMIC_VERIFICATION,
    TEXT_NO_FAILURES,
    TEXT_NO_FINDINGS_LIST,
    TEXT_NO_RESOLVED_EVIDENCE,
    TEXT_NO_REVIEWS,
    TEXT_NOTE_IMMUTABLE,
    TEXT_NOTE_TRACEABLE,
    TEXT_PARTIAL_NO_FAILURE,
    TEXT_POC_PENDING,
    TEXT_REVIEW_MODEL,
    TEXT_REVIEW_OUTCOME,
    TEXT_REVIEW_RATIONALE,
    TEXT_REVIEW_REFS,
    TEXT_REVIEW_TIME,
    TEXT_RISK_HIGH_TAIL,
    TEXT_RISK_NONE,
    TEXT_RISK_TAIL,
    TEXT_RUN_LOG,
    TEXT_STATUS_NONE,
    TEXT_TOTAL_NONE,
    confidence_band,
    enum_zh,
    failure_kind_zh,
    finding_confirmation_reasons,
    finding_has_strong_evidence,
    finding_is_model_inferred,
    generic_fix,
    impact_text,
    raw_value,
    sort_findings,
    zh_with_original,
)
from vulnweaver_reporting.context import CodeExcerpt, ReportContext
from vulnweaver_reporting.stats import (
    STATUS_ROWS,
    dataflow_labels,
    group_pocs,
    highest_severity,
    location_parts,
    nonempty_status_summary,
    severity_counts,
    severity_label,
    status_counts,
)

#: Poc results that mean dynamic verification produced no usable conclusion.
_INCONCLUSIVE_POC_RESULTS = frozenset(
    {"tool_error", "environment_error", "timeout", "policy_denied", "inconclusive"}
)


@dataclass(frozen=True)
class KeyValueTable:
    """Two-column key/value table with central Chinese headers."""

    rows: tuple[tuple[str, str], ...]
    headers: tuple[str, str] = (LABEL_ITEM, LABEL_CONTENT)


@dataclass(frozen=True)
class DataTable:
    """Multi-column table with a Chinese header row."""

    headers: tuple[str, ...]
    rows: tuple[tuple[str, ...], ...]


@dataclass(frozen=True)
class BulletList:
    """Unordered bullet items."""

    items: tuple[str, ...]


@dataclass(frozen=True)
class Paragraph:
    """A single paragraph of prose."""

    text: str


@dataclass(frozen=True)
class Marker:
    """A speculation warning rendered prominently before or after conclusions."""

    text: str


@dataclass(frozen=True)
class CodeBlock:
    """A bounded code excerpt with its immutable source identity."""

    excerpt: CodeExcerpt


@dataclass(frozen=True)
class Section:
    """One report section; level mirrors the heading depth (2 for chapters)."""

    level: int
    title: str
    blocks: tuple[Block, ...]
    kind: str = ""
    anchor: str = ""
    reference: str = ""


Block = KeyValueTable | DataTable | BulletList | Paragraph | Marker | CodeBlock | Section


@dataclass(frozen=True)
class ReportModel:
    """Complete format-neutral report content."""

    title: str
    sections: tuple[Section, ...]
    metrics: tuple[tuple[str, int], ...] = ()
    task_id: str = "未提供"
    generated_at: str = "未提供"


def build_report_model(
    findings: Sequence[Finding],
    pocs: Sequence[Poc] = (),
    evidence: Mapping[str, list[Evidence]] | None = None,
    context: ReportContext | None = None,
) -> ReportModel:
    """Assemble the full Chinese report model from persisted scan results."""
    ordered = sort_findings(findings)
    grouped_pocs = group_pocs(pocs)
    resolved_evidence = evidence or {}
    ctx = context if context is not None else ReportContext()
    blocked_pocs = [
        poc
        for poc in pocs
        if poc["result"] is not None and raw_value(poc["result"]) in _INCONCLUSIVE_POC_RESULTS
    ]
    model_only_count = sum(
        1
        for finding in ordered
        if finding_is_model_inferred(
            _supporting_evidence(finding, resolved_evidence.get(finding["id"], []), ctx)
        )
    )
    sections = (
        _summary_sections(ordered, blocked_pocs, model_only_count, ctx),
        _statistics_sections(ordered),
        _finding_sections(ordered, grouped_pocs, resolved_evidence, ctx),
        _appendix_sections(ordered, ctx, resolved_evidence),
    )
    counts = status_counts(ordered)
    return ReportModel(
        title=REPORT_TITLE,
        sections=tuple(sections),
        metrics=(
            ("已确认漏洞", counts["confirmed"]),
            ("待确认问题", sum(counts[key] for key in ("candidate", "disputed", "unverifiable"))),
            ("已排除误报", counts["false_positive"]),
            ("动态验证记录", len(pocs)),
        ),
        task_id=ctx.get("task_id") or MISSING,
        generated_at=ctx.get("generated_at") or MISSING,
    )


def _summary_sections(
    findings: Sequence[Finding],
    blocked_pocs: Sequence[Poc],
    model_only_count: int,
    ctx: ReportContext,
) -> Section:
    rows = (
        (LABEL_SAMPLE, _samples_text(ctx)),
        (LABEL_TASK_ID, _task_id_text(ctx)),
        (LABEL_TASK_RESULT, _task_result_text(ctx)),
        (LABEL_FINDING_TOTAL, _finding_total_text(findings)),
        (LABEL_STATUS_SUMMARY, _status_text(findings)),
        (LABEL_OVERALL_RISK, _overall_risk_text(findings, ctx)),
    )
    limits = _limitation_items(findings, blocked_pocs, model_only_count, ctx)
    return Section(
        level=2,
        kind="summary",
        title=f"1. {SECTION_SUMMARY}",
        blocks=(
            KeyValueTable(rows=rows),
            Section(
                level=3,
                title=SECTION_LIMITS,
                blocks=(BulletList(items=limits),),
            ),
        ),
    )


def _statistics_sections(findings: Sequence[Finding]) -> Section:
    severities = severity_counts(
        [f for f in findings if raw_value(f["status"]) != "false_positive"]
    )
    statuses = status_counts(findings)
    severity_rows = tuple(
        (zh_with_original(SEVERITY_ZH, value), str(severities[value])) for value in SEVERITY_ZH
    )
    status_rows = tuple(
        (zh_with_original(FINDING_STATUS_ZH, value), str(statuses[value])) for value in STATUS_ROWS
    )
    return Section(
        level=2,
        kind="statistics",
        title=f"2. {SECTION_STATS}",
        blocks=(
            Section(
                level=3,
                title=f"2.1 {SECTION_SEVERITY_DISTRIBUTION}（不含误报）",
                blocks=(DataTable(headers=(LABEL_SEVERITY, LABEL_COUNT), rows=severity_rows),),
            ),
            Section(
                level=3,
                title=f"2.2 {SECTION_STATUS_DISTRIBUTION}",
                blocks=(DataTable(headers=(LABEL_STATUS, LABEL_COUNT), rows=status_rows),),
            ),
        ),
    )


def _finding_sections(
    findings: Sequence[Finding],
    grouped_pocs: Mapping[str, list[Poc]],
    evidence: Mapping[str, list[Evidence]],
    ctx: ReportContext,
) -> Section:
    blocks: list[Block] = []
    if not findings:
        blocks.append(Paragraph(text=TEXT_NO_FINDINGS_LIST))
    for index, finding in enumerate(findings, start=1):
        blocks.append(
            _finding_section(
                index,
                finding,
                grouped_pocs.get(finding["id"], []),
                evidence.get(finding["id"], []),
                ctx,
            )
        )
    return Section(level=2, title=f"3. {SECTION_FINDINGS}", blocks=tuple(blocks), kind="findings")


def _finding_section(
    index: int,
    finding: Finding,
    pocs: Sequence[Poc],
    finding_evidence: Sequence[Evidence],
    ctx: ReportContext,
) -> Section:
    severity = zh_with_original(SEVERITY_ZH, finding["severity"])
    category = zh_with_original(FINDING_CATEGORY_ZH, finding["category"])
    severity_plain = enum_zh(SEVERITY_ZH, finding["severity"])
    category_plain = enum_zh(FINDING_CATEGORY_ZH, finding["category"])
    title = _one_line(finding["title"])
    relations = ctx.get("evidence_relations", {}).get(finding["id"], {})
    supporting = _supporting_evidence(finding, finding_evidence, ctx)
    model_inferred = finding_is_model_inferred(supporting)
    heading = f"3.{index}【{severity_plain} · {category_plain}】{title}（{finding['cwe_id']}）"
    blocks: list[Block] = []
    if not finding_has_strong_evidence(supporting):
        blocks.append(
            Marker(text=SPECULATIVE_NOTE + (MODEL_INFERRED_MARK if model_inferred else ""))
        )
    elif model_inferred:
        blocks.append(Marker(text=MODEL_INFERRED_MARK))
    location, location_kind, function_name = location_parts(finding)
    where = f"{location}（{location_kind}）"
    if function_name:
        where = f"{location}（{location_kind}，函数 {function_name}）"
    blocks += [
        KeyValueTable(
            rows=(
                (LABEL_FINDING_ID, finding["id"]),
                (LABEL_SEVERITY, severity),
                (
                    LABEL_CONFIDENCE,
                    f"{finding['confidence']:.2f}（{confidence_band(finding['confidence'])}）",
                ),
                (LABEL_STATUS, zh_with_original(FINDING_STATUS_ZH, finding["status"])),
                (LABEL_CATEGORY, category),
                (LABEL_LOCATION, where),
            )
        ),
        *_code_blocks(finding, ctx),
        Section(
            level=4,
            title=SUBSECTION_TRIGGER,
            kind="call-path",
            blocks=(
                BulletList(items=_call_path_items(finding)),
                Paragraph(
                    text="触发输入、权限与保护条件请结合下列证据核查；调用关系本身不代表已完成漏洞复现。"
                ),
            ),
        ),
        Section(
            level=4,
            title=SUBSECTION_EVIDENCE,
            reference=f"evidence-{finding['id']}",
            blocks=(
                BulletList(
                    items=tuple(
                        f"E{number:02d} · "
                        f"{_relation_text(relations.get(item['id'], 'supports'))} · "
                        f"{enum_zh(EVIDENCE_TYPE_ZH, item['type'])} · "
                        f"{enum_zh(EVIDENCE_STRENGTH_ZH, item['strength'])}"
                        for number, item in enumerate(finding_evidence, start=1)
                    )
                    or (TEXT_NO_RESOLVED_EVIDENCE,)
                ),
            ),
        ),
        Section(
            level=4,
            title=SUBSECTION_IMPACT,
            blocks=(Paragraph(text=impact_text(finding)),),
        ),
        Section(
            level=4,
            title=SUBSECTION_FIX,
            blocks=(Paragraph(text=_remediation_text(finding)),),
        ),
        Section(
            level=4,
            title=SUBSECTION_VERIFICATION,
            blocks=(BulletList(items=_verification_items(pocs)),),
        ),
        Section(
            level=4,
            title=SUBSECTION_CONFIRMATION,
            blocks=(
                BulletList(
                    items=tuple(finding_confirmation_reasons(finding, supporting))
                    or (TEXT_NO_CONFIRMATION,)
                ),
            ),
        ),
    ]
    return Section(
        level=3,
        title=heading,
        blocks=tuple(blocks),
        kind=f"finding {raw_value(finding['severity'])}",
    )


def _code_blocks(finding: Finding, ctx: ReportContext) -> list[Block]:
    excerpt = ctx.get("excerpts", {}).get(finding["id"])
    if excerpt:
        return [CodeBlock(excerpt=excerpt)]
    reason = ctx.get("excerpt_errors", {}).get(finding["id"], "未提供可追溯的代码摘录")
    return [Paragraph(text=f"代码上下文：{reason}。")]


def _supporting_evidence(
    finding: Finding, evidence: Sequence[Evidence], ctx: ReportContext
) -> list[Evidence]:
    relations = ctx.get("evidence_relations", {}).get(finding["id"], {})
    return [item for item in evidence if relations.get(item["id"], "supports") == "supports"]


def _relation_text(value: str) -> str:
    return {"supports": "支持", "contradicts": "反驳", "contextual": "上下文"}.get(
        value, "关系未记录"
    )


def _appendix_sections(
    findings: Sequence[Finding],
    ctx: ReportContext,
    evidence: Mapping[str, list[Evidence]],
) -> Section:
    return Section(
        level=2,
        kind="appendix",
        title=f"4. {SECTION_APPENDIX}",
        blocks=(
            Section(
                level=3,
                title="证据索引与来源",
                blocks=tuple(
                    Section(
                        level=4,
                        title=finding["id"],
                        anchor=f"evidence-{finding['id']}",
                        blocks=(
                            BulletList(
                                items=_evidence_items(finding, evidence.get(finding["id"], [])),
                            ),
                        ),
                    )
                    for finding in findings
                ),
            ),
            Section(
                level=3,
                title=f"4.1 {SECTION_METADATA}",
                blocks=(
                    KeyValueTable(
                        rows=(
                            (LABEL_TASK_ID, _task_id_text(ctx)),
                            (LABEL_CREATED_AT, ctx.get("task_created_at") or MISSING),
                            (LABEL_UPDATED_AT, ctx.get("task_updated_at") or MISSING),
                            (LABEL_PRODUCED_BY, ctx.get("produced_by") or MISSING),
                        )
                    ),
                ),
            ),
            Section(
                level=3,
                title=f"4.2 {SECTION_FAILURES}",
                blocks=(BulletList(items=_failure_items(ctx)),),
            ),
            Section(
                level=3,
                title=f"4.3 {SECTION_REVIEWS}",
                blocks=(BulletList(items=_review_items(findings, ctx)),),
            ),
            Section(
                level=3,
                title=f"4.4 {SECTION_DATA_NOTES}",
                blocks=(BulletList(items=(TEXT_NOTE_IMMUTABLE, TEXT_NOTE_TRACEABLE)),),
            ),
        ),
    )


def _call_path_items(finding: Finding) -> tuple[str, ...]:
    items = [
        f"{enum_zh(CALL_PATH_RELATION_ZH, step['relation'])} "
        f"{_one_line(str(step['function_name'])[:2048])}（{_step_location(step)}）"
        for step in finding["call_path"]
    ]
    labels = dataflow_labels(finding)
    if labels:
        flow = " → ".join(_one_line(label) for label in labels[:32])
        items.append(f"{TEXT_DATAFLOW}{flow}")
    return tuple(items) or (TEXT_NO_CALL_PATH,)


def _evidence_items(finding: Finding, finding_evidence: Sequence[Evidence]) -> tuple[str, ...]:
    items = [
        f"{TEXT_EVIDENCE_REFS}：{_references(finding['evidence_ids'])}",
        f"{TEXT_REVIEW_REFS}：{_references(finding['review_ids'])}",
    ]
    if not finding_evidence:
        return tuple(items + [TEXT_NO_RESOLVED_EVIDENCE])
    for number, item in enumerate(finding_evidence, start=1):
        tool = item["tool"]
        tool_text = f"{tool['name']}@{tool['version']}" if tool else MISSING
        items.append(
            f"E{number:02d} · {item['id']}：{zh_with_original(EVIDENCE_TYPE_ZH, item['type'])}，"
            f"{enum_zh(EVIDENCE_STRENGTH_ZH, item['strength'])}，"
            f"{LABEL_EVIDENCE_TOOL} {tool_text}，"
            f"{LABEL_EVIDENCE_ARTIFACT} {item['artifact_ref']}"
            f"（{TEXT_EVIDENCE_DIGEST} {item['digest']}）"
        )
        stack_hash = item["replay_recipe"].get("stack_hash")
        if stack_hash:
            items.append(f"{item['id']} {TEXT_CRASH_STACK}：{stack_hash}")
        if item["exit_code"] is not None:
            items.append(f"{item['id']} {TEXT_EXIT_CODE}：{item['exit_code']}")
    return tuple(items)


def _verification_items(pocs: Sequence[Poc]) -> tuple[str, ...]:
    if not pocs:
        return (TEXT_NO_DYNAMIC_VERIFICATION,)
    items: list[str] = []
    for poc in pocs:
        result = (
            zh_with_original(POC_RESULT_ZH, poc["result"])
            if poc["result"] is not None
            else TEXT_POC_PENDING
        )
        run_log = f"；{TEXT_RUN_LOG} {poc['run_log_ref']}" if poc["run_log_ref"] else ""
        items.append(
            f"{poc['id']}：{enum_zh(POC_KIND_ZH, poc['kind'])}；"
            f"{LABEL_STATUS} {zh_with_original(POC_STATUS_ZH, poc['status'])}；"
            f"结果 {result}{run_log}"
        )
    return tuple(items)


def _limitation_items(
    findings: Sequence[Finding],
    blocked_pocs: Sequence[Poc],
    model_only_count: int,
    ctx: ReportContext,
) -> tuple[str, ...]:
    items: list[str] = []
    code = ctx.get("failure_code")
    if code:
        kind = failure_kind_zh(ctx.get("failure_kind") or MISSING)
        message = _one_line(ctx.get("failure_message") or "")
        items.append(f"{TEXT_LIMIT_FAILURE}：{kind}——{code}：{message}")
    if blocked_pocs:
        items.append(f"{len(blocked_pocs)} {TEXT_LIMIT_BLOCKED_POCS}")
    if model_only_count:
        items.append(f"{model_only_count} {TEXT_LIMIT_MODEL_ONLY}")
    items.extend(ctx.get("job_failures", []))
    if ctx.get("task_result") == "partial":
        items.append("本次分析覆盖不完整，请结合失败记录与待确认项理解结论。")
    return tuple(items) or (TEXT_NO_BLOCKERS,)


def _failure_items(ctx: ReportContext) -> tuple[str, ...]:
    failures = tuple(ctx.get("job_failures", []))
    code = ctx.get("failure_code")
    if code:
        kind = failure_kind_zh(ctx.get("failure_kind") or MISSING)
        message = _one_line(ctx.get("failure_message") or "")
        return (f"{kind}：{code}——{message}", *failures)
    if failures:
        return failures
    if ctx.get("task_result") == "partial":
        return (TEXT_PARTIAL_NO_FAILURE,)
    return (TEXT_NO_FAILURES,)


def _review_items(findings: Sequence[Finding], ctx: ReportContext) -> tuple[str, ...]:
    reviews = ctx.get("reviews") or {}
    items: list[str] = []
    for finding in findings:
        for review in reviews.get(finding["id"], []):
            items.append(
                f"{finding['id']}：{review['id']} {TEXT_REVIEW_OUTCOME} "
                f"{zh_with_original(FINDING_STATUS_ZH, review['outcome'])}；"
                f"{TEXT_REVIEW_MODEL} {review['model'] or MISSING}；"
                f"{TEXT_REVIEW_RATIONALE} {_one_line(review['rationale']) or MISSING}；"
                f"{TEXT_REVIEW_TIME} {review['created_at']}"
            )
    return tuple(items) or (TEXT_NO_REVIEWS,)


def _samples_text(ctx: ReportContext) -> str:
    samples = ctx.get("samples") or []
    if not samples:
        return MISSING
    return "；".join(
        f"{sample.get('name') or MISSING}"
        f"（{TEXT_EVIDENCE_DIGEST} {sample.get('digest') or MISSING}，"
        f"类型 {SAMPLE_KIND_ZH.get(sample.get('kind', ''), sample.get('kind', MISSING))}）"
        for sample in samples
    )


def _task_id_text(ctx: ReportContext) -> str:
    return ctx.get("task_id") or MISSING


def _task_result_text(ctx: ReportContext) -> str:
    result = ctx.get("task_result")
    if not result:
        return "阶段报告：任务尚未完成最终结算" if ctx.get("task_status") else MISSING
    label = TASK_RESULT_ZH.get(result, result)
    detail = TASK_RESULT_DETAIL_ZH.get(result, "")
    return f"{label}（{result}）：{detail}"


def _finding_total_text(findings: Sequence[Finding]) -> str:
    if not findings:
        return TEXT_TOTAL_NONE
    active = [f for f in findings if raw_value(f["status"]) != "false_positive"]
    if not active:
        return f"{len(findings)}（全部已排除为误报）"
    highest = highest_severity(active) or ""
    return f"{len(findings)}（{TEXT_HIGHEST_SEVERITY}：{severity_label(highest)}（{highest}））"


def _status_text(findings: Sequence[Finding]) -> str:
    summary = nonempty_status_summary(findings)
    return "，".join(summary) if summary else TEXT_STATUS_NONE


def _overall_risk_text(findings: Sequence[Finding], ctx: ReportContext | None = None) -> str:
    if not findings:
        if ctx and (
            ctx.get("task_result") in {"partial", "failed", "cancelled"}
            or (ctx.get("task_status") and not ctx.get("task_result"))
            or ctx.get("job_failures")
            or ctx.get("failure_code")
        ):
            return "覆盖不完整：暂未发现问题，不能据此排除漏洞。"
        return TEXT_RISK_NONE
    confirmed = [f for f in findings if raw_value(f["status"]) == "confirmed"]
    if not confirmed:
        pending = sum(raw_value(f["status"]) != "false_positive" for f in findings)
        return f"没有已确认漏洞；{pending} 项待确认问题，需依据证据完成复核。"
    highest = highest_severity(confirmed) or ""
    risk = {"critical": "严重", "high": "高", "medium": "中"}.get(highest, "低")
    text = (
        f"已确认漏洞总体风险等级评估为{risk}"
        f"（依据{TEXT_HIGHEST_SEVERITY} {severity_label(highest)}）。"
    )
    return text + (TEXT_RISK_HIGH_TAIL if highest in {"critical", "high"} else TEXT_RISK_TAIL)


def _remediation_text(finding: Finding) -> str:
    suggestion = _one_line(finding["fix_suggestion"])
    if not suggestion or suggestion.startswith("Address the audited pattern associated with CWE-"):
        return generic_fix(finding)
    return suggestion


def _references(ids: Sequence[str]) -> str:
    return ", ".join(ids) if ids else MISSING


def _step_location(step: Mapping[str, object]) -> str:
    path = step.get("path")
    if isinstance(path, str) and path:
        line = step.get("line")
        return f"{path[:4096]}:{line if isinstance(line, int) else 1}"
    address = step.get("address")
    return f"0x{address:x}" if isinstance(address, int) else "unknown"


def _one_line(value: str) -> str:
    """Collapse line breaks so a value stays on one report line."""
    return value.replace("\r", " ").replace("\n", " ").strip()
