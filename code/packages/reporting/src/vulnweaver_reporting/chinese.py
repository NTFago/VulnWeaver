"""Central Chinese copy, enum mappings, and copy templates for human-facing reports.

Every Chinese label used by the Markdown and HTML renderers lives here so the
wording stays consistent across formats. Mappings are keyed by the raw contract
enum values; unknown values fall back to ``MISSING`` so a report never invents
data that the scan results do not carry.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Final

from vulnweaver_contracts import Evidence, Finding

MISSING: Final[str] = "未提供"

#: Appended to any conclusion whose evidence is exclusively model-generated.
MODEL_INFERRED_MARK: Final[str] = "（模型推断，尚未经动态验证，需人工确认）"

#: Prefixed to report sections that lack any strong evidence.
SPECULATIVE_MARK: Final[str] = "【推测性内容】"

SPECULATIVE_NOTE: Final[str] = (
    f"{SPECULATIVE_MARK}本节缺少强证据支持，结论可能不成立，需人工复核后方可采信。"
)

SEVERITY_ORDER: Final[Mapping[str, int]] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "unknown": 5,
}

SEVERITY_ZH: Final[Mapping[str, str]] = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "info": "提示",
}

FINDING_STATUS_ZH: Final[Mapping[str, str]] = {
    "candidate": "候选",
    "confirmed": "已确认",
    "false_positive": "误报",
    "disputed": "争议",
    "unverifiable": "不可验证",
}

FINDING_CATEGORY_ZH: Final[Mapping[str, str]] = {
    "memory_corruption": "内存破坏",
    "injection": "注入",
    "auth_or_business_logic": "鉴权/业务逻辑",
    "static_only": "仅静态证据",
}

EVIDENCE_TYPE_ZH: Final[Mapping[str, str]] = {
    "model_explanation": "模型推断说明",
    "tool_output": "工具输出",
    "code_snippet": "源码片段",
    "dataflow_path": "数据流路径",
    "crash_record": "崩溃记录",
    "reproduction_result": "复现结果",
    "exploit_record": "利用记录",
    "review_conclusion": "复核结论",
    "human_confirmation": "人工确认",
}

EVIDENCE_STRENGTH_ZH: Final[Mapping[str, str]] = {
    "strong": "强证据",
    "supporting": "支持性证据",
    "contextual": "背景信息",
}

EVIDENCE_RELATION_ZH: Final[Mapping[str, str]] = {
    "supports": "支持",
    "contradicts": "相悖",
    "contextual": "背景",
}

CALL_PATH_RELATION_ZH: Final[Mapping[str, str]] = {
    "target": "漏洞目标函数",
    "caller": "调用方",
    "callee": "被调用方",
}

POC_KIND_ZH: Final[Mapping[str, str]] = {
    "proof_of_concept": "概念验证（Poc）",
    "exploit": "利用验证（Exploit）",
}

POC_STATUS_ZH: Final[Mapping[str, str]] = {
    "created": "已创建",
    "queued": "排队中",
    "running": "执行中",
    "completed": "已完成",
    "failed": "失败",
    "cancelled": "已取消",
}

POC_RESULT_ZH: Final[Mapping[str, str]] = {
    "exploitable": "可利用",
    "not_exploitable_under_environment": "当前环境下不可利用",
    "inconclusive": "结果不确定",
    "tool_error": "工具错误",
    "environment_error": "环境错误",
    "timeout": "超时",
    "policy_denied": "策略拒绝",
}

TASK_RESULT_ZH: Final[Mapping[str, str]] = {
    "success": "分析成功",
    "partial": "部分成功",
    "no_findings": "未发现漏洞",
}

TASK_RESULT_DETAIL_ZH: Final[Mapping[str, str]] = {
    "success": "分析流程执行完成并产出结构化发现。",
    "partial": "部分分析阶段失败或受限，已产出可复核的发现；详情见附录失败原因汇总。",
    "no_findings": "分析流程执行完成，未报告任何漏洞发现。",
}

SAMPLE_KIND_ZH: Final[Mapping[str, str]] = {
    "source_archive": "源码压缩包",
    "source_repository": "源码仓库",
    "elf": "ELF 二进制",
    "pe": "PE 二进制",
    "derived": "派生工件",
}

_FAILURE_KIND_ZH: Final[Mapping[str, str]] = {
    "validation": "输入校验失败",
    "policy": "安全策略拒绝",
    "timeout": "超时",
    "tool": "工具故障",
    "environment": "环境故障",
    "dependency": "依赖故障",
    "cancelled": "已取消",
    "internal": "内部错误",
}

_STATUSES_NEEDING_CONFIRMATION: Final[frozenset[str]] = frozenset(
    {"candidate", "disputed", "unverifiable"}
)


def enum_zh(mapping: Mapping[str, str], value: object) -> str:
    """Map a contract enum (or its raw value) to the central Chinese label."""
    raw = getattr(value, "value", value)
    return mapping.get(raw, MISSING) if isinstance(raw, str) else MISSING


def zh_with_original(mapping: Mapping[str, str], value: object) -> str:
    """Render ``中文（original）`` keeping the raw enum value for traceability."""
    raw = getattr(value, "value", value)
    label = enum_zh(mapping, raw)
    original = raw if isinstance(raw, str) else MISSING
    if label is MISSING and original is MISSING:
        return MISSING
    return f"{label}（{original}）"


def raw_value(value: object) -> str:
    """Return the raw enum string so numbers, identifiers, and paths stay verbatim."""
    member = getattr(value, "value", value)
    return member if isinstance(member, str) else str(member)


def confidence_band(confidence: float) -> str:
    """Translate the numeric confidence into a bounded Chinese band."""
    if confidence >= 0.8:
        return "高可信"
    if confidence >= 0.6:
        return "较可信"
    if confidence >= 0.4:
        return "中等可信（待验证）"
    if confidence >= 0.2:
        return "低可信"
    return "极低可信（推测性）"


def severity_rank(severity: object) -> int:
    """Sort key placing the most severe findings first; unknown values last."""
    return SEVERITY_ORDER.get(raw_value(severity), SEVERITY_ORDER["unknown"])


def sort_findings(findings: Sequence[Finding]) -> list[Finding]:
    """Order findings by descending severity while keeping a stable input order."""
    return sorted(findings, key=lambda finding: severity_rank(finding["severity"]))


def finding_has_strong_evidence(finding_evidence: Sequence[Evidence]) -> bool:
    """Return True when at least one evidence item carries strong strength."""
    return any(raw_value(item["strength"]) == "strong" for item in finding_evidence)


def finding_is_model_inferred(finding_evidence: Sequence[Evidence]) -> bool:
    """Return True when every linked evidence item is a model explanation.

    A finding without any evidence at all also counts as model inferred: its
    conclusions then rest solely on the analysing model and must be marked.
    """
    if not finding_evidence:
        return True
    return all(raw_value(item["type"]) == "model_explanation" for item in finding_evidence)


def finding_confirmation_reasons(
    finding: Finding, finding_evidence: Sequence[Evidence]
) -> list[str]:
    """List the concrete reasons why a finding still needs human confirmation."""
    reasons: list[str] = []
    status = raw_value(finding["status"])
    if status in _STATUSES_NEEDING_CONFIRMATION:
        label = zh_with_original(FINDING_STATUS_ZH, finding["status"])
        reasons.append(f"当前状态为{label}，尚未确认为真实漏洞。")
    if finding_is_model_inferred(finding_evidence):
        reasons.append("关联证据均为模型推断说明，缺少工具输出、崩溃记录或运行结果等客观证据。")
    elif not finding_has_strong_evidence(finding_evidence):
        reasons.append("现有证据中不含强证据，结论强度有限。")
    return reasons


def impact_text(finding: Finding) -> str:
    """Compose the category-specific Chinese impact template with finding facts."""
    severity = enum_zh(SEVERITY_ZH, finding["severity"])
    category = raw_value(finding["category"])
    if category == "memory_corruption":
        return (
            "该问题属于内存破坏类缺陷：受影响位置附近的内存访问缺乏足够的边界约束，"
            f"若攻击者能控制相关输入的长度或内容，可能导致进程崩溃、信息泄露或任意代码执行。"
            f"当前评估等级为{severity}，可信度 {finding['confidence']:.2f}"
            f"（{confidence_band(finding['confidence'])}）。"
        )
    if category == "injection":
        return (
            "该问题属于注入类缺陷：外部可控数据未经充分校验即进入敏感执行环节，"
            f"可能造成命令注入、代码注入或查询注入。当前评估等级为{severity}，"
            f"可信度 {finding['confidence']:.2f}（{confidence_band(finding['confidence'])}）。"
        )
    if category == "auth_or_business_logic":
        return (
            "该问题属于鉴权或业务逻辑类缺陷：相关检查可能被绕过或未在服务端强制执行，"
            f"可导致越权访问、业务状态异常或权限提升。当前评估等级为{severity}，"
            f"可信度 {finding['confidence']:.2f}（{confidence_band(finding['confidence'])}）。"
        )
    return (
        "该问题目前仅有静态分析证据支持，实际可利用性尚未经动态验证："
        f"可能为真实缺陷，也可能受编译器、运行环境等因素影响而不成立。"
        f"当前评估等级为{severity}，可信度 {finding['confidence']:.2f}"
        f"（{confidence_band(finding['confidence'])}）。"
    )


def generic_fix(finding: Finding) -> str:
    """Compose the category-level fallback remediation, explicitly marked generic."""
    category = raw_value(finding["category"])
    if category == "memory_corruption":
        detail = (
            "在受影响位置引入边界与长度检查，改用带边界保护的安全函数"
            "（如 snprintf、memcpy_s），并启用编译期加固选项"
            "（栈保护、ASLR、DEP）后重新构建。"
        )
    elif category == "injection":
        detail = (
            "避免将外部输入拼接到命令、查询或代码中，改用参数化接口或白名单校验，"
            "对特殊字符做转义，并以最小权限运行相关处理逻辑。"
        )
    elif category == "auth_or_business_logic":
        detail = (
            "在服务端强制执行鉴权与业务规则，对关键操作补充权限校验、"
            "状态机完整性检查与审计日志，并限制重试与并发。"
        )
    else:
        detail = (
            "先构造最小化触发用例，在隔离沙箱中复现以确认可利用性，"
            "再依据验证结论制定针对性修复方案。"
        )
    return f"（通用建议，该发现未提供修复建议）{detail}"


def failure_kind_zh(kind: object) -> str:
    """Map a structured failure kind to Chinese, keeping the original readable."""
    return zh_with_original(_FAILURE_KIND_ZH, kind)


# ---------------------------------------------------------------------------
# Report copy: every static Chinese string used by the report model lives here.
# ---------------------------------------------------------------------------

REPORT_TITLE: Final[str] = "VulnWeaver 中文审计报告"

SECTION_SUMMARY: Final[str] = "执行摘要"
SECTION_STATS: Final[str] = "风险统计"
SECTION_SEVERITY_DISTRIBUTION: Final[str] = "严重等级分布"
SECTION_STATUS_DISTRIBUTION: Final[str] = "确认状态分布"
SECTION_FINDINGS: Final[str] = "漏洞列表"
SECTION_APPENDIX: Final[str] = "附录"
SECTION_LIMITS: Final[str] = "主要限制"
SECTION_METADATA: Final[str] = "任务元数据"
SECTION_FAILURES: Final[str] = "失败原因汇总"
SECTION_REVIEWS: Final[str] = "复核历史"
SECTION_DATA_NOTES: Final[str] = "数据说明"
SUBSECTION_TRIGGER: Final[str] = "触发条件与调用路径"
SUBSECTION_EVIDENCE: Final[str] = "证据链明细"
SUBSECTION_IMPACT: Final[str] = "影响分析"
SUBSECTION_FIX: Final[str] = "修复建议"
SUBSECTION_VERIFICATION: Final[str] = "验证状态"
SUBSECTION_CONFIRMATION: Final[str] = "待人工确认项"

LABEL_ITEM: Final[str] = "项目"
LABEL_CONTENT: Final[str] = "内容"
LABEL_COUNT: Final[str] = "数量"
LABEL_SAMPLE: Final[str] = "被测样本"
LABEL_TASK_ID: Final[str] = "任务编号"
LABEL_TASK_RESULT: Final[str] = "任务结论"
LABEL_FINDING_TOTAL: Final[str] = "发现漏洞总数"
LABEL_STATUS_SUMMARY: Final[str] = "确认状态"
LABEL_OVERALL_RISK: Final[str] = "总体风险结论"
LABEL_FINDING_ID: Final[str] = "漏洞编号"
LABEL_SEVERITY: Final[str] = "严重等级"
LABEL_CONFIDENCE: Final[str] = "可信度"
LABEL_STATUS: Final[str] = "状态"
LABEL_CATEGORY: Final[str] = "类别"
LABEL_LOCATION: Final[str] = "受影响位置"
LABEL_CREATED_AT: Final[str] = "创建时间"
LABEL_UPDATED_AT: Final[str] = "最后更新"
LABEL_PRODUCED_BY: Final[str] = "报告工具"
LABEL_EVIDENCE_ID: Final[str] = "证据 ID"
LABEL_EVIDENCE_TYPE: Final[str] = "类型"
LABEL_EVIDENCE_STRENGTH: Final[str] = "强度"
LABEL_EVIDENCE_TOOL: Final[str] = "来源工具"
LABEL_EVIDENCE_ARTIFACT: Final[str] = "工件引用"

TEXT_NO_FINDINGS_LIST: Final[str] = (
    "本次任务未报告任何漏洞发现。若预期应有输出，请检查分析阶段日志与样本格式支持范围。"
)
TEXT_RISK_NONE: Final[str] = (
    "低：本次任务未发现漏洞。该结论受当前分析覆盖范围限制，不代表样本绝对安全。"
)
TEXT_RISK_HIGH_TAIL: Final[str] = "存在高等级问题，建议立即安排人工复核并优先处置。"
TEXT_RISK_TAIL: Final[str] = "建议按严重等级安排复核与修复。"
TEXT_STATUS_NONE: Final[str] = "无发现"
TEXT_TOTAL_NONE: Final[str] = "0（未发现漏洞）"
TEXT_HIGHEST_SEVERITY: Final[str] = "最高严重等级"
TEXT_NO_BLOCKERS: Final[str] = "本次扫描未记录到阶段失败、降级或验证受阻事件。"
TEXT_LIMIT_FAILURE: Final[str] = "任务记录到结构化失败"
TEXT_LIMIT_BLOCKED_POCS: Final[str] = (
    "次动态验证未取得有效结论（工具错误、环境错误、超时、策略拒绝或结果不确定），"
    "相关发现的动态可信度受限。"
)
TEXT_LIMIT_MODEL_ONLY: Final[str] = (
    "个发现的证据仅为模型推断说明，已在对应章节标注「需人工确认」。"
)
TEXT_NO_CALL_PATH: Final[str] = "静态分析未能固化调用路径。"
TEXT_DATAFLOW: Final[str] = "数据流："
TEXT_EVIDENCE_REFS: Final[str] = "证据引用"
TEXT_REVIEW_REFS: Final[str] = "复核引用"
TEXT_NO_RESOLVED_EVIDENCE: Final[str] = "本发现没有已解析的证据记录。"
TEXT_CRASH_STACK: Final[str] = "崩溃栈哈希"
TEXT_EXIT_CODE: Final[str] = "工具退出码"
TEXT_EVIDENCE_DIGEST: Final[str] = "内容摘要"
TEXT_NO_DYNAMIC_VERIFICATION: Final[str] = (
    "未执行动态验证：该发现没有关联的 Poc 执行记录。"
)
TEXT_POC_PENDING: Final[str] = "未提供（执行未完成）"
TEXT_RUN_LOG: Final[str] = "运行日志"
TEXT_NO_CONFIRMATION: Final[str] = "无。"
TEXT_NO_FAILURES: Final[str] = "本次任务没有失败记录。"
TEXT_PARTIAL_NO_FAILURE: Final[str] = (
    "任务结论为部分成功（partial），但未记录结构化失败原因。"
)
TEXT_REVIEW_OUTCOME: Final[str] = "结论"
TEXT_REVIEW_MODEL: Final[str] = "复核模型"
TEXT_REVIEW_RATIONALE: Final[str] = "理由"
TEXT_REVIEW_TIME: Final[str] = "时间"
TEXT_NO_REVIEWS: Final[str] = "本次任务没有已登记的复核记录。"
TEXT_NOTE_IMMUTABLE: Final[str] = (
    "原始工具输出与运行日志以不可变工件引用保存，本报告仅嵌入引用，不复制原始内容。"
)
TEXT_NOTE_TRACEABLE: Final[str] = (
    "全部结论均可追溯到扫描结果字段；字段缺失时显示「未提供」。"
)
