<script lang="ts">
  import type { AgentRun } from "@vulnweaver/contracts";
  import { formatDuration } from "../format";
  import { failureCodeText, runStatusLabels } from "../i18n";
  import { agentRoles, displayRuns, sharedReferences, type AuditTrail } from "../audit-trail";

  /** 多智能体协作面板：按运行记录渲染角色卡片，运行中的智能体带脉冲状态。 */

  export let agentRuns: AgentRun[] = [];
  export let trail: AuditTrail | null = null;
  export let trailError = "";
  $: runs = displayRuns(agentRuns, trail);

  $: runningCount = agentRuns.filter((run) => run.status === "running").length;
</script>

<div class="agent-cards">
  <p class="trail-note">按实际运行记录展示分工。共享引用仅说明输入输出衔接，不代表自动确认漏洞。</p>
  {#if trailError}<p class="failure">{trailError}；原始运行记录仍可查看。</p>{/if}
  {#if agentRuns.length === 0}
    <div class="compact-empty">模型分析运行后，此处将展示各智能体的决策轨迹。</div>
  {:else}
    <div class="agent-summary">
      <span class="badge muted">{agentRuns.length} 条运行</span>
      {#if runningCount > 0}<span class="badge accent"><i class="pulse-dot" aria-hidden="true"></i>{runningCount} 个运行中</span>{/if}
    </div>
    {#each runs as run (run.id)}
      <article class="agent-card" class:running={run.status === "running"}>
        <header>
          <span class={`status-dot ${run.status}`} aria-hidden="true"></span>
          <b class="role">{agentRoles[run.role] ?? agentRoles.unknown}</b>
          <span class={`run-state ${run.status}`}>{runStatusLabels[run.status]}</span>
        </header>
        <small class="model" title={run.model}>{run.model}</small>
        {#if run.job_id}<small class="trace-ref">作业 {run.job_id}{run.job_attempt !== null ? ` · 第 ${run.job_attempt} 次尝试` : ""}</small>{/if}
        <div class="meta">
          <span>决策 {run.decisions.length}</span>
          <span>输入 {run.token_usage.input_tokens} · 输出 {run.token_usage.output_tokens}</span>
          <span>{typeof run.duration_ms === "number" ? `耗时 ${formatDuration(run.duration_ms) || "不足 1 秒"}` : run.status === "running" ? "运行中" : "未记录耗时"}</span>
        </div>
        {#if run.decisions.length > 0}
          <details class="run-decisions"><summary>查看 {run.decisions.length} 条决策</summary><ol>{#each run.decisions as decision}<li><code>{decision.decision}</code><span>{decision.reason}</span></li>{/each}</ol></details>
        {/if}
        {#if run.failure}
          <p class="failure">{failureCodeText(run.failure.code)}{run.failure.message ? ` · ${run.failure.message}` : ""}</p>
        {/if}
        {#if run.tool_steps.length}
          <details><summary>调查工具 · {run.tool_steps.length} 步</summary><ol class="tool-steps">{#each run.tool_steps as step}<li><b>{step.tool ?? step.step_id}</b><span>{step.succeeded ? "执行成功" : "执行失败"}</span>{#if step.failure_code}<code>{step.failure_code}</code>{/if}</li>{/each}</ol><small class="trail-note">此处展示已登记决策；未记录的工具观察内容不会补写。</small></details>
        {/if}
        <details class="references"><summary>输入 / 输出 · {run.input_refs.length} / {run.result_refs?.length ?? 0}</summary><b>输入引用</b>{#each run.input_refs as ref}<code>{ref}</code>{:else}<small>未登记</small>{/each}<b>输出引用</b>{#each run.result_refs ?? [] as ref}<code>{ref}</code>{:else}<small>未登记</small>{/each}</details>
        {#each sharedReferences(runs, run) as link}<p class="handoff">已登记引用衔接：{link.role} → 本次运行（{link.refs.length} 项）</p>{/each}
      </article>
    {/each}
  {/if}
</div>

<style>
  .trail-note { font-size: 12px; color: var(--muted); margin: 0; }
  .trace-ref { font-size: 11px; color: var(--muted); overflow-wrap: anywhere; }
  summary { font-size: 12px; color: var(--text-2); cursor: pointer; }
  .references code { display: block; margin: 5px 0; font-size: 11px; overflow-wrap: anywhere; white-space: pre-wrap; }
  .references b { display: block; margin-top: 10px; font-size: 12px; }
  .tool-steps { display: grid; gap: 8px; padding-left: 20px; font-size: 12px; }
  .tool-steps span { color: var(--muted); margin-left: 12px; }
  .handoff { margin: 0; color: var(--accent); font-size: 12px; }
  .agent-cards { display: grid; gap: 12px; margin: 0; }
  .agent-summary { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }
  .agent-summary .badge i { margin: 0; }
  .pulse-dot {
    display: inline-block;
    width: 7px;
    height: 7px;
    border-radius: 999px;
    background: currentColor;
    animation: agent-pulse 1.6s var(--ease) infinite;
  }
  .agent-card {
    display: grid;
    gap: 7px;
    padding: 14px 16px;
    background: var(--panel-2);
    border: 1px solid var(--line);
    border-radius: var(--radius-s);
    transition: border-color 0.16s var(--ease), box-shadow 0.16s var(--ease);
  }
  .agent-card.running {
    border-color: rgba(201, 244, 59, 0.45);
    box-shadow: 0 0 0 1px rgba(201, 244, 59, 0.2);
  }
  .agent-card header { display: flex; align-items: center; gap: 10px; min-width: 0; }
  .role { font-size: 13.5px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .run-state {
    margin-left: auto;
    flex: 0 0 auto;
    font: 600 11px/1.2 var(--font-mono);
    letter-spacing: 0.03em;
    color: var(--muted);
  }
  .run-state.running { color: var(--accent); }
  .run-state.succeeded { color: var(--ok); }
  .run-state.failed { color: #ff9d8e; }
  .agent-card.running .status-dot { animation: agent-pulse 1.6s var(--ease) infinite; }
  .model {
    font: 500 11.5px/1.4 var(--font-mono);
    color: var(--muted);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .meta { display: flex; flex-wrap: wrap; gap: 6px 16px; }
  .meta span {
    font: 500 11.5px/1.5 var(--font-mono);
    color: var(--text-2);
    font-variant-numeric: tabular-nums;
  }
  .failure { margin: 0; color: #ff9d8e; font-size: 12px; line-height: 1.55; overflow-wrap: anywhere; }
  @keyframes agent-pulse {
    0%, 100% { box-shadow: 0 0 0 0 rgba(201, 244, 59, 0.4); }
    50% { box-shadow: 0 0 0 4px rgba(201, 244, 59, 0.07); }
  }
  @media (prefers-reduced-motion: reduce) { .pulse-dot, .agent-card.running .status-dot { animation: none; } }
</style>
