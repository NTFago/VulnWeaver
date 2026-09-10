<script lang="ts">
  import type { AgentRun } from "@vulnweaver/contracts";
  import { formatDuration } from "../format";
  import { agentRoleLabel, failureCodeText, runStatusLabels } from "../i18n";

  /** 多智能体协作面板：按运行记录渲染角色卡片，运行中的智能体带脉冲状态。 */

  export let agentRuns: AgentRun[] = [];

  $: runningCount = agentRuns.filter((run) => run.status === "running").length;
</script>

<div class="agent-cards">
  {#if agentRuns.length === 0}
    <div class="compact-empty">模型分析运行后，此处将展示各智能体的决策轨迹。</div>
  {:else}
    <div class="agent-summary">
      <span class="badge muted">{agentRuns.length} 条运行</span>
      {#if runningCount > 0}<span class="badge accent"><i class="pulse-dot" aria-hidden="true"></i>{runningCount} 个运行中</span>{/if}
    </div>
    {#each agentRuns as run (run.id)}
      <article class="agent-card" class:running={run.status === "running"}>
        <header>
          <span class={`status-dot ${run.status}`} aria-hidden="true"></span>
          <b class="role">{agentRoleLabel(run)}</b>
          <span class={`run-state ${run.status}`}>{runStatusLabels[run.status]}</span>
        </header>
        <small class="model" title={run.model}>{run.model}</small>
        <div class="meta">
          <span>决策 {run.decisions.length}</span>
          <span>token {run.token_usage.input_tokens}/{run.token_usage.output_tokens}</span>
          <span>{typeof run.duration_ms === "number" ? `耗时 ${formatDuration(run.duration_ms)}` : "运行中"}</span>
        </div>
        {#if run.failure}
          <p class="failure">{failureCodeText(run.failure.code)}{run.failure.message ? ` · ${run.failure.message}` : ""}</p>
        {/if}
      </article>
    {/each}
  {/if}
</div>

<style>
  .agent-cards { display: grid; gap: 12px; margin-top: 16px; }
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
</style>
