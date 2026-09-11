import type { AgentRun, JobStatus, QueueEvent } from "@vulnweaver/contracts";
export interface AuditTrailRun extends Omit<AgentRun, "schema_version" | "task_id" | "duration_ms"> {
  duration_ms: number | null;
  role: string; job_id: string | null; job_attempt: number | null;
  association: "exact_run_id_rule_with_attempt" | "exact_run_id_rule" | "unknown";
  tool_steps: { step_id: string; tool: string | null; succeeded: boolean; failure_code: string | null; observation: Record<string, unknown> | null; observation_status: "not_recorded" }[];
}
export interface AuditTrail {
  schema_version: "1.0.0"; task_id: string; agent_runs: AuditTrailRun[];
  binary_analysis_jobs: { job_id: string; status: JobStatus; attempt: number; input_refs: string[]; output_version_ids: string[]; facts_status: "not_exposed" }[];
}
export const agentRoles: Record<string, string> = {
  semantic_audit: "语义审计", semantic_audit_agent: "审计调查智能体", reverse_analysis_planner: "逆向规划智能体",
  readable_pseudocode: "伪代码可读化", fuzz_harness_generator: "模糊测试 Harness 生成", critical_logic_analyst: "关键逻辑分析",
  exploit_generator: "利用验证生成", independent_reviewer: "独立复核", unknown: "模型分析 · 角色未标注",
};
export function displayRuns(runs: AgentRun[], trail: AuditTrail | null): AuditTrailRun[] {
  const metadata = new Map(trail?.agent_runs.map(run => [run.id, run]) ?? []);
  return runs.map(run => metadata.get(run.id) ?? { ...run, duration_ms: run.duration_ms ?? null, role: "unknown", job_id: null, job_attempt: null, association: "unknown", tool_steps: [] });
}
export function sharedReferences(runs: AuditTrailRun[], target: AuditTrailRun) {
  return runs.filter(run => run.id !== target.id).flatMap(run => {
    const refs = (run.result_refs ?? []).filter(ref => target.input_refs.includes(ref));
    return refs.length ? [{ runId: run.id, role: agentRoles[run.role] ?? agentRoles.unknown, refs }] : [];
  });
}
export function mergeEvents(current: QueueEvent[], incoming: QueueEvent[]): QueueEvent[] {
  return [...new Map([...current, ...incoming].map(event => [event.event_id, event])).values()].sort((a, b) => a.sequence - b.sequence);
}
