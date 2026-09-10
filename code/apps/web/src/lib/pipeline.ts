import type { Job, JobKind } from "@vulnweaver/contracts";
import { formatDuration } from "./format";
import { failureCodeText } from "./i18n";

/**
 * 审计阶段流水线的纯聚合逻辑：把任务现有 Job 按 8 个固定审计阶段聚合。
 * 阶段 2/3 依赖任务输入类型选择 JobKind；后端的结构解析与逆向/静态扫描
 * 在同一类分析作业内执行，因此同类型任务的两个阶段聚合同一 JobKind，
 * 以标签区分语义（源码任务阶段 3 显示「静态扫描」）。
 */

export type PipelineTaskType = "source" | "binary";

export type StageStatus = "pending" | "running" | "succeeded" | "partial" | "failed" | "cancelled" | "skipped";

type StageDef = {
  key: string;
  icon: string;
  name: Record<PipelineTaskType, string>;
  kinds: Record<PipelineTaskType, JobKind[]>;
};

const stages: StageDef[] = [
  { key: "ingest", icon: "▤", name: { source: "样本导入", binary: "样本导入" }, kinds: { source: ["validate", "import"], binary: ["validate", "import"] } },
  { key: "structure", icon: "⛁", name: { source: "结构解析", binary: "结构解析" }, kinds: { source: ["source_analysis"], binary: ["binary_analysis"] } },
  { key: "reverse", icon: "⚙", name: { source: "静态扫描", binary: "逆向还原" }, kinds: { source: ["source_analysis"], binary: ["binary_analysis"] } },
  { key: "audit", icon: "⌕", name: { source: "语义审计", binary: "语义审计" }, kinds: { source: ["semantic_audit"], binary: ["semantic_audit"] } },
  { key: "review", icon: "⛨", name: { source: "独立复核", binary: "独立复核" }, kinds: { source: ["review"], binary: ["review"] } },
  { key: "fuzz", icon: "⚡", name: { source: "模糊测试", binary: "模糊测试" }, kinds: { source: ["fuzz"], binary: ["fuzz"] } },
  { key: "verify", icon: "✦", name: { source: "验证与利用", binary: "验证与利用" }, kinds: { source: ["proof", "exploit"], binary: ["proof", "exploit"] } },
  { key: "report", icon: "▣", name: { source: "报告生成", binary: "报告生成" }, kinds: { source: ["report"], binary: ["report"] } },
];

export const stageStatusLabels: Record<StageStatus, string> = {
  pending: "等待",
  running: "运行中",
  succeeded: "完成",
  partial: "部分完成",
  failed: "失败",
  cancelled: "已取消",
  skipped: "未启用",
};

export type StageView = {
  key: string;
  icon: string;
  name: string;
  status: StageStatus;
  done: number;
  total: number;
  failedIds: string[];
  failureText: string;
  durationText: string;
};

function aggregateStage(def: StageDef, jobs: Job[], taskType: PipelineTaskType): StageView {
  const kinds = def.kinds[taskType];
  const stageJobs = jobs.filter((job) => kinds.includes(job.kind));
  const base: StageView = {
    key: def.key, icon: def.icon, name: def.name[taskType],
    status: "pending", done: 0, total: stageJobs.length, failedIds: [], failureText: "", durationText: "",
  };
  if (stageJobs.length === 0) {
    // 源码任务不会创建模糊测试作业：该阶段按「未启用」展示。
    base.status = def.key === "fuzz" && taskType === "source" ? "skipped" : "pending";
    return base;
  }
  const running = stageJobs.filter((job) => job.status === "running" || job.status === "waiting_permission");
  const succeeded = stageJobs.filter((job) => job.status === "succeeded");
  const failed = stageJobs.filter((job) => job.status === "failed");
  const cancelled = stageJobs.filter((job) => job.status === "cancelled");
  let status: StageStatus;
  if (running.length > 0) status = "running";
  else if (failed.length > 0) status = succeeded.length > 0 ? "partial" : "failed";
  else if (cancelled.length > 0) status = succeeded.length > 0 ? "partial" : "cancelled";
  else if (succeeded.length === stageJobs.length) status = "succeeded";
  else status = "pending";
  base.status = status;
  base.done = succeeded.length;
  base.failedIds = failed.map((job) => job.id);
  if (failed.length > 0) {
    const reasonSource = [...failed].sort((a, b) => b.updated_at.localeCompare(a.updated_at))[0];
    const code = reasonSource.failure ? failureCodeText(reasonSource.failure.code) : "";
    const message = reasonSource.failure?.message ?? "";
    base.failureText = [code, message].filter(Boolean).join(" · ").slice(0, 160);
  }
  const startTimes = stageJobs.map((job) => Date.parse(job.created_at)).filter((t) => Number.isFinite(t));
  const endTimes = stageJobs.map((job) => Date.parse(job.updated_at)).filter((t) => Number.isFinite(t));
  if (startTimes.length > 0 && endTimes.length > 0) {
    const span = Math.max(...endTimes) - Math.min(...startTimes);
    base.durationText = formatDuration(span);
  }
  return base;
}

export function aggregatePipelineStages(jobs: Job[], taskType: PipelineTaskType): StageView[] {
  return stages.map((def) => aggregateStage(def, jobs, taskType));
}

export interface PipelineProgress {
  completed: number;
  applicable: number;
  percent: number;
  currentStageName: string;
}

export function pipelineProgress(stageViews: StageView[]): PipelineProgress {
  const applicable = stageViews.filter((stage) => stage.status !== "skipped");
  const completed = applicable.filter((stage) => stage.status === "succeeded").length;
  return {
    completed,
    applicable: applicable.length,
    percent: applicable.length > 0 ? Math.round((completed / applicable.length) * 100) : 0,
    currentStageName: stageViews.find((stage) => stage.status === "running")?.name ?? "",
  };
}
