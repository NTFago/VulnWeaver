/**
 * VulnWeaver 界面中文文案中心。
 * 枚举、状态与失败码的中文映射统一在此维护；日志原文、代码、路径与错误码原文不做翻译。
 */

import type {
  EvidenceStrength,
  EvidenceType,
  FindingCategory,
  FindingStatus,
  JobKind,
  JobStatus,
  PocKind,
  PocResult,
  PocStatus,
  RunStatus,
  Severity,
  TaskResult,
  TaskStatus,
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
