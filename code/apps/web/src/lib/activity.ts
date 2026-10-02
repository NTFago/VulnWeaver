/**
 * 任务活动（liveness）信号的纯函数处理：结构签名、心跳分级、耗时与日志格式化。
 * 后端 /api/tasks/{id}/activity 是轻量快照；这里决定哪些变化值得全量刷新、
 * 前端如何把时间戳翻译成"后台还在工作"的可读反馈。
 */

export interface ActivityJob {
  id: string;
  kind: string;
  tool_name: string | null;
  status: string;
  attempt: number;
  created_at: string;
  updated_at: string;
  lease_expires_at: string | null;
  failure_code: string | null;
}

export interface ActivityRun {
  id: string;
  status: string;
  model: string;
  created_at: string;
  updated_at: string;
  duration_ms: number | null;
  decision_count: number;
  latest_decision: string | null;
  latest_decision_reason: string | null;
  latest_decision_at: string | null;
  input_tokens: number | null;
  output_tokens: number | null;
  failure_code: string | null;
}

export interface ActivityJournalEntry {
  round?: number;
  kind?: string;
  summary?: string;
}

export interface ActivityAuditProgress {
  rounds: number;
  completed: boolean;
  model_label: string | null;
  updated_at: string;
  input_tokens: number | null;
  output_tokens: number | null;
  journal_tail: ActivityJournalEntry[];
}

export interface TaskActivity {
  schema_version: "1.0.0";
  task_id: string;
  task_status: string;
  task_updated_at: string;
  jobs: ActivityJob[];
  runs: ActivityRun[];
  audit_progress: ActivityAuditProgress | null;
  latest_activity_at: string | null;
  events: unknown[];
}

export interface Heartbeat {
  level: "live" | "stale" | "idle" | "none";
  secondsAgo: number | null;
}

/** 结构签名：作业状态/尝试次数或运行状态变化时，全量读模型才需要刷新。 */
export function activitySignature(activity: TaskActivity): string {
  const jobs = [...activity.jobs]
    .map((job) => `${job.id}:${job.status}:${job.attempt}`)
    .sort()
    .join("|");
  const runs = [...activity.runs]
    .map((run) => `${run.id}:${run.status}`)
    .sort()
    .join("|");
  return `${activity.task_status}#${jobs}#${runs}`;
}

export function activityChanged(previous: TaskActivity | null, next: TaskActivity): boolean {
  return previous === null || activitySignature(previous) !== activitySignature(next);
}

/** 心跳分级：job 心跳 30s 一次，90s 内算活着；超过 10 分钟按静默处理。 */
export function heartbeat(latestActivityAt: string | null, nowMs: number): Heartbeat {
  if (!latestActivityAt) return { level: "none", secondsAgo: null };
  const then = Date.parse(latestActivityAt);
  if (Number.isNaN(then)) return { level: "none", secondsAgo: null };
  const secondsAgo = Math.max(0, Math.round((nowMs - then) / 1000));
  if (secondsAgo < 90) return { level: "live", secondsAgo };
  if (secondsAgo < 600) return { level: "stale", secondsAgo };
  return { level: "idle", secondsAgo };
}

export function formatAgo(seconds: number | null): string {
  if (seconds === null) return "未知";
  if (seconds < 5) return "刚刚";
  if (seconds < 60) return `${seconds} 秒前`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} 分钟前`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} 小时 ${minutes % 60} 分前`;
  return `${Math.floor(hours / 24)} 天前`;
}

/** 已用时长：小时/分钟/秒三层，运行中的任务看得到自己跑了多久。 */
export function formatElapsedSince(startedAt: string, nowMs: number): string {
  const start = Date.parse(startedAt);
  if (Number.isNaN(start)) return "未知";
  const seconds = Math.max(0, Math.floor((nowMs - start) / 1000));
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const rest = seconds % 60;
  if (hours > 0) return `${hours} 小时 ${minutes} 分`;
  if (minutes > 0) return `${minutes} 分 ${rest} 秒`;
  return `${rest} 秒`;
}

/** 调查日志尾部：每条一行"第 N 轮 · 摘要"，给 AgentPanel 直接渲染。 */
export function journalLines(entries: ActivityJournalEntry[], limit = 3): string[] {
  return entries
    .slice(-limit)
    .map((entry) => {
      const round = typeof entry.round === "number" ? `第 ${entry.round} 轮 · ` : "";
      return `${round}${entry.summary ?? ""}`.trim();
    })
    .filter(Boolean);
}

export const heartbeatLabels: Record<Heartbeat["level"], string> = {
  live: "后台工作中",
  stale: "活动变慢",
  idle: "长时间无活动",
  none: "暂无活动记录",
};
