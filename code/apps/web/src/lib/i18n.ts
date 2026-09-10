/**
 * VulnWeaver 界面中文文案中心。
 * 枚举、状态与失败码的中文映射统一在此维护；日志原文、代码、路径与错误码原文不做翻译。
 */

import type {
  AgentRun,
  EvidenceStrength,
  EvidenceType,
  FindingCategory,
  FindingStatus,
  JobKind,
  JobStatus,
  JobRequestedPayload,
  JobStatusChangedPayload,
  PocKind,
  PocResult,
  PocStatus,
  QueueEvent,
  RunStatus,
  Severity,
  TaskRequestedPayload,
  TaskResult,
  TaskStatus,
  TaskStatusChangedPayload,
} from "@vulnweaver/contracts";

export const taskStatusLabels: Record<TaskStatus, string> = {
  created: "已登记",
  validating: "校验中",
  analyzing: "分析中",
  reviewing: "复核中",
  verifying: "验证中",
  exploiting: "利用验证",
  reporting: "报告中",
  completed: "已完成",
  failed: "已失败",
  cancelled: "已取消",
};

export const taskResultLabels: Record<TaskResult, string> = {
  success: "已产生候选结果",
  partial: "部分完成：有执行单元未成功",
  no_findings: "扫描已完成，未发现候选问题",
};

export const jobKindLabels: Record<JobKind, string> = {
  validate: "样本校验",
  import: "样本导入",
  source_analysis: "源码分析",
  semantic_audit: "语义审计",
  binary_analysis: "二进制分析",
  review: "独立复核",
  fuzz: "模糊测试",
  proof: "概念验证",
  exploit: "利用验证",
  report: "报告生成",
};

export const jobStatusLabels: Record<JobStatus, string> = {
  pending: "等待",
  queued: "排队中",
  running: "运行中",
  waiting_permission: "等待许可",
  succeeded: "已完成",
  failed: "已失败",
  cancelled: "已取消",
};

export const findingStatusLabels: Record<FindingStatus, string> = {
  candidate: "候选",
  confirmed: "已确认",
  false_positive: "误报",
  disputed: "有争议",
  unverifiable: "不可验证",
};

export const findingCategoryLabels: Record<FindingCategory, string> = {
  memory_corruption: "内存破坏",
  injection: "注入",
  auth_or_business_logic: "认证或业务逻辑",
  static_only: "仅静态发现",
};

export const severityLabels: Record<Severity, string> = {
  critical: "严重",
  high: "高危",
  medium: "中危",
  low: "低危",
  info: "提示",
};

export const evidenceTypeLabels: Record<EvidenceType, string> = {
  model_explanation: "模型解释",
  tool_output: "工具输出",
  code_snippet: "代码片段",
  dataflow_path: "数据流路径",
  crash_record: "崩溃记录",
  reproduction_result: "复现结果",
  exploit_record: "利用记录",
  review_conclusion: "复核结论",
  human_confirmation: "人工确认",
};

export const evidenceStrengthLabels: Record<EvidenceStrength, string> = {
  contextual: "背景参考",
  supporting: "支持性",
  strong: "强证据",
};

export const pocKindLabels: Record<PocKind, string> = {
  proof_of_concept: "概念验证",
  exploit: "利用脚本",
};

export const pocStatusLabels: Record<PocStatus, string> = {
  created: "已创建",
  queued: "排队中",
  running: "运行中",
  completed: "已完成",
  failed: "已失败",
  cancelled: "已取消",
};

export const pocResultLabels: Record<PocResult, string> = {
  exploitable: "可利用",
  not_exploitable_under_environment: "当前环境下不可利用",
  inconclusive: "无法定论",
  tool_error: "工具错误",
  environment_error: "环境错误",
  timeout: "超时",
  policy_denied: "策略拒绝",
};

export const runStatusLabels: Record<RunStatus, string> = {
  created: "已创建",
  running: "运行中",
  succeeded: "已完成",
  failed: "已失败",
  cancelled: "已取消",
};

/** 置信度档位：≥0.8 高、≥0.5 中、其余为低。 */
export type ConfidenceTier = "high" | "medium" | "low";

export function confidenceTier(value: number): ConfidenceTier {
  return value >= 0.8 ? "high" : value >= 0.5 ? "medium" : "low";
}

export const confidenceTierLabels: Record<ConfidenceTier, string> = {
  high: "高",
  medium: "中",
  low: "低",
};

/**
 * 结构化失败码的中文摘要（尽力映射）。
 * 未命中的失败码以「错误码：」前缀展示原文，保留可检索性。
 */
export const failureCodeLabels: Record<string, string> = {
  "fuzz.request_required": "模糊测试请求缺少必要参数",
  "fuzz.request_invalid": "模糊测试请求不合法",
  "fuzz.invalid_request": "模糊测试请求不合法",
  "fuzz.harness_unconfigured": "模糊测试 Harness 未配置",
  "fuzz.harness_fixtures_invalid": "模糊测试种子样例不合法",
  "fuzz.sandbox_failed": "模糊测试沙箱执行失败",
  "fuzz.execution_failed": "模糊测试执行失败",
  "fuzz.crash_budget_exceeded": "崩溃数超出模糊测试预算上限",
  "fuzz.crash_evidence_rejected": "模糊测试崩溃证据未通过校验",
  "fuzz.crash_finding_required": "模糊测试结果缺少崩溃发现",
  "fuzz.crash_sink_unconfigured": "崩溃汇聚点未配置",
  "fuzz.internal_error": "模糊测试内部错误",
  "fuzz.invalid_job_kind": "作业类型与模糊测试执行器不符",
  "fuzz.job_id_mismatch": "模糊测试结果的作业编号不一致",
  "fuzz.result_invalid": "模糊测试结果不合法",
  "fuzz.executor_unconfigured": "模糊测试执行器未配置",
  "proof.request_required": "验证请求缺少必要参数",
  "proof.invalid_request": "验证请求不合法",
  "proof.auto_requires_exploit_kind": "自动利用必须使用利用验证作业类型",
  "proof.script_ref_outside_project": "脚本引用不属于本项目",
  "proof.executor_unconfigured": "验证执行器未配置",
  "proof.invalid_job_kind": "作业类型与验证执行器不符",
  "review.finding_id_required": "复核作业缺少 Finding 标识",
  "review.finding_not_found": "复核目标 Finding 不存在",
  "review.model_unconfigured": "复核模型未配置",
  "review.model_budget_exhausted": "复核模型 token 预算已用尽",
  "review.executor_unconfigured": "复核执行器未配置",
  "review.invalid_job_kind": "作业类型与复核执行器不符",
  "semantic_audit.model_unconfigured": "语义审计模型未配置",
  "semantic_audit.model_budget_exhausted": "语义审计 token 预算已用尽",
  "semantic_audit.artifact_unavailable": "语义审计所需工件不可用",
  "semantic_audit.no_output": "语义审计未产生输出",
  "semantic_audit.executor_unconfigured": "语义审计执行器未配置",
  "semantic_audit.invalid_job_kind": "作业类型与语义审计执行器不符",
  "report.arguments_required": "报告作业缺少必要参数",
  "report.artifact_target_required": "报告作业未指定样本目标",
  "report.artifact_mismatch": "报告目标与任务样本不一致",
  "report.format_unsupported": "报告格式不受支持",
  "report.invalid_request": "报告请求不合法",
  "report.invalid_job_kind": "作业类型与报告执行器不符",
  "report.executor_unconfigured": "报告执行器未配置",
  "source_import.invalid_input_count": "源码导入的输入数量不正确",
  "source_import.invalid_arguments": "源码导入参数不合法",
  "source_import.invalid_job_kind": "作业类型与源码导入执行器不符",
  "source_import.parent_artifact_missing": "源码导入的父工件缺失",
  "source_import.derived_artifact_conflict": "源码派生工件冲突",
  "source_import.index_validation_failed": "源码索引校验失败",
  "source_import.persistence_unavailable": "工件存储暂不可用",
  "source_import.persistence_integrity_failed": "工件存储完整性校验失败",
  "source_import.environment_error": "源码导入执行环境错误",
  "binary_import.invalid_input_count": "二进制导入的输入数量不正确",
  "binary_import.invalid_arguments": "二进制导入参数不合法",
  "binary_import.invalid_job_kind": "作业类型与二进制导入执行器不符",
  "binary_import.invalid_artifact_kind": "样本类型与二进制管线不符",
  "binary_import.input_missing": "二进制导入输入缺失",
  "binary_import.input_not_authorized": "二进制输入未获授权",
  "binary_import.invalid_tool": "二进制工具未登记",
  "binary_import.invalid_target_addresses": "分析目标地址不合法",
  "binary_import.target_outside_executable_section": "目标地址不在可执行节内",
  "binary_import.too_many_target_addresses": "分析目标地址数量过多",
  "binary_import.derived_artifact_conflict": "二进制派生工件冲突",
  "binary_import.object_ref_mismatch": "工件引用不一致",
  "binary_import.project_mismatch": "工件不属于当前项目",
  "binary_import.pair_validation_failed": "调用关系校验失败",
  "binary_import.pair_integrity_failed": "调用关系完整性校验失败",
  "binary_import.pair_persistence_failed": "调用关系写入失败",
  "binary_import.readable_pseudocode_too_large": "伪代码体积超出上限",
  "binary_import.result_validation_failed": "二进制分析结果校验失败",
  "binary_import.executor_unconfigured": "二进制执行器未配置",
  "binary_import.environment_error": "二进制导入执行环境错误",
  "binary_import.persistence_unavailable": "工件存储暂不可用",
  "binary_import.persistence_integrity_failed": "工件存储完整性校验失败",
  "sandbox.timeout": "沙箱执行超时",
  "sandbox.timeout_exceeded": "沙箱执行超出时限",
  "sandbox.resource_budget_exceeded": "沙箱资源预算超限",
  "sandbox.output_limit_exceeded": "沙箱输出超出上限",
  "sandbox.tool_not_registered": "工具未在注册表中登记",
  "sandbox.tool_failed": "沙箱内工具执行失败",
  "sandbox.image_identity_mismatch": "镜像身份与登记不一致",
  "sandbox.isolation_policy_rejected": "隔离策略拒绝该请求",
  "sandbox.arguments_rejected": "沙箱参数被拒绝",
  "sandbox.artifact_kind_rejected": "沙箱拒绝该样本类型",
  "sandbox.command_profile_missing": "缺少命令执行档案",
  "sandbox.command_profile_invalid": "命令执行档案不合法",
  "sandbox.input_or_command_invalid": "沙箱输入或命令不合法",
  "sandbox.request_invalid": "沙箱请求不合法",
  "sandbox.runtime_failed": "容器运行时失败",
  "sandbox.transport_failed": "沙箱通信失败",
  "sandbox.output_collection_failed": "沙箱输出收集失败",
  "sandbox.cleanup_failed": "沙箱清理失败",
  "sandbox.cancelled": "沙箱执行已取消",
  "sandbox.runner_internal_error": "沙箱执行器内部错误",
  "worker.attempts_exhausted": "重试次数已用尽",
  "worker.execution_error": "执行单元运行错误",
};

export function failureCodeText(code: string): string {
  return failureCodeLabels[code] ?? `错误码：${code}`;
}

/* ---------- 事件流 ---------- */

/** 事件展示分类：左侧色条与类型徽章的依据。 */
export type EventCategory = "stage" | "job" | "finding" | "error" | "system";

export const eventCategoryLabels: Record<EventCategory, string> = {
  stage: "阶段",
  job: "作业",
  finding: "发现",
  error: "错误",
  system: "系统",
};

export type EventFilter = "all" | EventCategory;

export function eventCategory(event: QueueEvent): EventCategory {
  const rawType: string = event.event_type;
  if (rawType === "task.requested") return "stage";
  if (rawType === "task.status_changed") return "stage";
  if (rawType === "job.status_changed") {
    const payload = event.payload as JobStatusChangedPayload;
    return payload.failure ? "error" : "job";
  }
  if (rawType === "job.requested") return "job";
  // 未来可能新增的事件类型：按名称关键词兜底分类。
  if (rawType.includes("finding")) return "finding";
  if (rawType.includes("error") || rawType.includes("failed")) return "error";
  return "system";
}

/** 过滤 chips 的匹配规则：作业过滤包含失败的作业事件（其展示分类是「错误」）。 */
export function eventMatchesFilter(event: QueueEvent, filter: EventFilter): boolean {
  if (filter === "all") return true;
  if (filter === "job") return event.event_type === "job.requested" || event.event_type === "job.status_changed";
  return eventCategory(event) === filter;
}

/** 事件标题中文化；未映射的事件类型显示原文。 */
export function eventTitle(event: QueueEvent, jobKindById: Map<string, JobKind>): string {
  const rawType: string = event.event_type;
  if (rawType === "task.requested") {
    const payload = event.payload as TaskRequestedPayload;
    return payload.artifact_version_ids.length > 1 ? `任务已受理（${payload.artifact_version_ids.length} 个样本）` : "任务已受理";
  }
  if (rawType === "task.status_changed") {
    const payload = event.payload as TaskStatusChangedPayload;
    return `任务状态：${taskStatusLabels[payload.status]}`;
  }
  if (rawType === "job.requested") {
    const payload = event.payload as JobRequestedPayload;
    return `作业已下发：${jobKindLabels[payload.job_kind]}`;
  }
  if (rawType === "job.status_changed") {
    const payload = event.payload as JobStatusChangedPayload;
    const kindLabel = jobKindById.get(payload.job_id);
    const base = kindLabel
      ? `作业 ${kindLabel} ${jobStatusLabels[payload.status]}`
      : `作业 ${jobStatusLabels[payload.status]}`;
    return payload.failure ? `${base}：${failureCodeText(payload.failure.code)}` : base;
  }
  return rawType;
}

/* ---------- 智能体协作 ---------- */

const agentRoleKeywords: Array<{ keywords: string[]; label: string }> = [
  { keywords: ["key_logic", "key logic", "critical", "关键"], label: "关键逻辑" },
  { keywords: ["reverse", "ghidra", "deobfusc", "disassembl", "逆向"], label: "逆向分析" },
  { keywords: ["fuzz", "afl", "harness", "模糊"], label: "模糊测试" },
  { keywords: ["exploit", "利用"], label: "利用生成" },
  { keywords: ["proof", "verif"], label: "验证" },
  { keywords: ["review", "复核"], label: "独立复核" },
  { keywords: ["static", "semgrep", "scan", "audit", "静态", "语义"], label: "静态审计" },
  { keywords: ["import", "ingest", "parse", "导入"], label: "导入解析" },
  { keywords: ["plan", "orchestr", "dispatch", "schedul", "调度"], label: "调度" },
  { keywords: ["report", "summar", "报告"], label: "报告" },
];

/** 依据运行记录中可能的智能体标识字段与模型名推断中文角色名；无法识别时显示「模型分析」。 */
export function agentRoleLabel(run: AgentRun): string {
  const hints = run as unknown as Record<string, unknown>;
  const haystack = [hints.agent, hints.agent_type, hints.role, hints.stage, hints.kind, run.model]
    .filter((hint): hint is string => typeof hint === "string" && hint.trim().length > 0)
    .join(" ")
    .toLowerCase();
  if (haystack) {
    for (const entry of agentRoleKeywords) {
      if (entry.keywords.some((keyword) => haystack.includes(keyword))) return entry.label;
    }
  }
  return "模型分析";
}
