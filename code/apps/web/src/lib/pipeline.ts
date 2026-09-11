import type { Job, JobKind, Project, Task } from "@vulnweaver/contracts";
import { failureCodeText } from "./i18n";

export type PipelineTaskType = "source" | "binary" | "mixed";
export type StageStatus = "pending" | "queued" | "running" | "waiting_permission" | "succeeded" | "partial" | "failed" | "cancelled" | "not_scheduled" | "skipped";
export const stageStatusLabels: Record<StageStatus, string> = {
  pending: "等待调度", queued: "排队中", running: "运行中", waiting_permission: "等待许可",
  succeeded: "已完成", partial: "部分完成", failed: "失败", cancelled: "已取消",
  not_scheduled: "未执行", skipped: "未启用",
};
export interface StageView {
  key: string; name: string; description: string; status: StageStatus;
  jobs: Job[]; done: number; total: number; failureText: string;
}
type StageDefinition = { key: string; name: string; description: string; kinds: JobKind[]; dynamic?: boolean };
const definitions: StageDefinition[] = [
  { key: "input", name: "导入与解析", description: "登记样本、建立索引；二进制导入可包含识别与逆向处理。", kinds: ["validate", "import"] },
  { key: "analysis", name: "分析基线", description: "已调度的静态扫描或二进制分析作业。", kinds: ["source_analysis", "binary_analysis"] },
  { key: "audit", name: "智能体审计", description: "按需读取函数、追踪调用并调查候选漏洞。", kinds: ["semantic_audit"] },
  { key: "review", name: "独立复核", description: "核查候选结论、支持证据与反驳证据。", kinds: ["review"] },
  { key: "fuzz", name: "模糊测试", description: "按项目设置与候选条件调度，源码可经 Harness 编译后执行。", kinds: ["fuzz"], dynamic: true },
  { key: "verify", name: "漏洞验证", description: "概念验证与已授权的利用验证；是否执行取决于证据及策略。", kinds: ["proof", "exploit"] },
  { key: "report", name: "报告生成", description: "汇总扫描事实、证据与复核记录，登记报告工件。", kinds: ["report"] },
];
export const terminalJobStatuses = new Set(["succeeded", "failed", "cancelled"]);
export const terminalTaskStatuses = new Set(["completed", "failed", "cancelled"]);
export function uniqueJobs(jobs: Job[]): Job[] {
  return [...new Map(jobs.map(job => [job.id, job])).values()];
}
export function aggregatePipelineStages(jobs: Job[], taskType: PipelineTaskType, task?: Task, project?: Project | null): StageView[] {
  return definitions.map(def => {
    const items = uniqueJobs(jobs).filter(job => def.kinds.includes(job.kind));
    const success = items.filter(job => job.status === "succeeded").length;
    const failed = items.filter(job => job.status === "failed");
    const cancelled = items.some(job => job.status === "cancelled");
    let status: StageStatus = "pending";
    if (!items.length) {
      if (def.dynamic && project?.exploit_validation_enabled === false) status = "skipped";
      else if (task && terminalTaskStatuses.has(task.status)) status = "not_scheduled";
    } else if (items.some(job => job.status === "running")) status = "running";
    else if (items.some(job => job.status === "waiting_permission")) status = "waiting_permission";
    else if (items.some(job => job.status === "queued")) status = "queued";
    else if (items.some(job => job.status === "pending")) status = "pending";
    else if (failed.length) status = success ? "partial" : "failed";
    else if (cancelled) status = success ? "partial" : "cancelled";
    else status = "succeeded";
    const failure = [...failed].sort((a, b) => b.updated_at.localeCompare(a.updated_at))[0]?.failure;
    return {
      key: def.key, name: def.key === "input" && taskType !== "source" ? "导入与逆向" : def.name,
      description: def.description, status, jobs: items, total: items.length, done: success,
      failureText: failure ? `${failureCodeText(failure.code)} · ${failure.message}` : "",
    };
  });
}
export function pipelineProgress(stages: StageView[]) {
  const jobs = uniqueJobs(stages.flatMap(stage => stage.jobs));
  const settled = jobs.filter(job => terminalJobStatuses.has(job.status)).length;
  return {
    settled, total: jobs.length, succeeded: jobs.filter(job => job.status === "succeeded").length,
    failed: jobs.filter(job => job.status === "failed").length,
    percent: jobs.length ? Math.round(settled / jobs.length * 100) : 0,
    activeNames: stages.filter(stage => ["running", "waiting_permission"].includes(stage.status)).map(stage => stage.name),
  };
}
