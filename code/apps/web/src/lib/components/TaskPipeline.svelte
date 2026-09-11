<script lang="ts">
  import type { Job } from "@vulnweaver/contracts";
  import { aggregatePipelineStages, pipelineProgress, stageStatusLabels, type PipelineTaskType } from "../pipeline";

  /** 审计阶段流水线视图：聚合规则见 lib/pipeline.ts。 */

  export let jobs: Job[] = [];
  export let taskType: PipelineTaskType = "source";
  export let taskStatus: string | undefined = undefined;
  export let busy = false;
  export let onRetryStage: (jobIds: string[]) => void = () => {};

  $: stageViews = aggregatePipelineStages(jobs, taskType, taskStatus);
  $: progressInfo = pipelineProgress(stageViews);
</script>

<section class="pipeline-panel" aria-label="审计阶段流水线">
  <ol class="pipeline">
    {#each stageViews as stage, index (stage.key)}
      <li class={`stage ${stage.status}`} class:current={stage.status === "running"} aria-current={stage.status === "running" ? "step" : undefined}>
        <div class="stage-head">
          <span class="stage-icon" aria-hidden="true">{stage.icon}</span>
          <span class="stage-order">{index + 1}</span>
        </div>
        <b class="stage-name">{stage.name}</b>
        <span class={`stage-state ${stage.status}`}><i class="dot" aria-hidden="true"></i>{stageStatusLabels[stage.status]}</span>
        {#if stage.total > 0}
          <span class="stage-count">{stage.done}/{stage.total} 作业</span>
        {/if}
        {#if stage.durationText}
          <span class="stage-duration">耗时 {stage.durationText}</span>
        {/if}
        {#if stage.failureText}
          <span class="stage-failure" title={stage.failureText}>{stage.failureText}</span>
        {/if}
        {#if stage.failedIds.length > 0}
          <button class="text-button stage-retry" disabled={busy} on:click={() => onRetryStage(stage.failedIds)}>重试（{stage.failedIds.length}）</button>
        {/if}
      </li>
    {/each}
  </ol>
  <div class="pipeline-progress">
    <div class="track" role="progressbar" aria-label="审计总体进度" aria-valuemin="0" aria-valuemax="100" aria-valuenow={progressInfo.percent}>
      <i style={`width: ${progressInfo.percent}%`}></i>
    </div>
    <span>{progressInfo.completed}/{progressInfo.applicable} 阶段完成{progressInfo.currentStageName ? ` · 当前：${progressInfo.currentStageName}` : ""}</span>
  </div>
</section>

<style>
  .pipeline-panel {
    background: var(--panel);
    border: 1px solid var(--line);
    border-radius: var(--radius-m);
    padding: 18px 18px 14px;
    margin-bottom: 24px;
  }
  .pipeline {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    grid-template-columns: repeat(8, minmax(0, 1fr));
    gap: 26px 26px;
  }
  .stage {
    position: relative;
    display: grid;
    gap: 5px;
    align-content: start;
    padding: 13px 14px;
    background: var(--panel-2);
    border: 1px solid var(--line);
    border-radius: var(--radius-m);
    transition: border-color 0.16s var(--ease), box-shadow 0.16s var(--ease), opacity 0.16s var(--ease);
  }
  /* 阶段之间的连接线 */
  .stage:not(:last-child)::after {
    content: "";
    position: absolute;
    top: 26px;
    right: -22px;
    width: 18px;
    height: 2px;
    background: var(--line-strong);
  }
  .stage.current {
    border-color: rgba(201, 244, 59, 0.6);
    box-shadow: 0 0 0 1px rgba(201, 244, 59, 0.3), 0 8px 22px -12px rgba(201, 244, 59, 0.35);
  }
  .stage.skipped {
    border-style: dashed;
    opacity: 0.72;
  }
  .stage-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
  }
  .stage-icon {
    font-size: 19px;
    line-height: 1;
    color: var(--text-2);
  }
  .stage-order {
    font: 600 10.5px/1 var(--font-mono);
    color: var(--muted);
    border: 1px solid var(--line);
    border-radius: 999px;
    padding: 3px 8px;
  }
  .stage.current .stage-icon { color: var(--accent); }
  .stage.succeeded .stage-icon { color: var(--ok); }
  .stage.failed .stage-icon, .stage.partial .stage-icon { color: var(--warn); }
  .stage-name {
    font-size: 13.5px;
    font-weight: 650;
    letter-spacing: 0.01em;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .stage-state {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font: 600 11px/1.2 var(--font-mono);
    letter-spacing: 0.03em;
    color: var(--muted);
  }
  .stage-state .dot {
    width: 7px;
    height: 7px;
    border-radius: 999px;
    background: #6f766c;
    flex: 0 0 7px;
  }
  .stage.running .stage-state { color: var(--accent); }
  .stage.running .stage-state .dot { background: var(--accent); animation: pipeline-pulse 1.6s var(--ease) infinite; }
  .stage.succeeded .stage-state { color: var(--ok); }
  .stage.succeeded .stage-state .dot { background: var(--ok); }
  .stage.failed .stage-state { color: #ff9d8e; }
  .stage.failed .stage-state .dot { background: var(--danger); }
  .stage.partial .stage-state { color: var(--warn); }
  .stage.partial .stage-state .dot { background: var(--warn); }
  .stage.cancelled .stage-state .dot { background: #6f766c; }
  .stage-count, .stage-duration {
    font: 500 11px/1.4 var(--font-mono);
    color: var(--muted);
    font-variant-numeric: tabular-nums;
  }
  .stage-failure {
    color: #ff9d8e;
    font-size: 11.5px;
    line-height: 1.5;
    display: -webkit-box;
    -webkit-line-clamp: 2;
    line-clamp: 2;
    -webkit-box-orient: vertical;
    overflow: hidden;
    overflow-wrap: anywhere;
  }
  .stage-retry {
    justify-self: start;
    margin-top: 2px;
    color: var(--warn);
    font-size: 12px;
    padding: 3px 8px;
  }
  .stage-retry:hover { color: var(--text); }
  .pipeline-progress {
    display: grid;
    grid-template-columns: minmax(0, 1fr) auto;
    align-items: center;
    gap: 16px;
    margin-top: 16px;
    padding-top: 14px;
    border-top: 1px solid var(--line);
  }
  .pipeline-progress .track {
    height: 6px;
    border-radius: 999px;
    background: var(--field);
    border: 1px solid var(--line);
    overflow: hidden;
  }
  .pipeline-progress .track i {
    display: block;
    height: 100%;
    border-radius: 999px;
    background: var(--accent);
    transition: width 0.4s var(--ease);
  }
  .pipeline-progress > span {
    font: 500 12px/1.4 var(--font-mono);
    color: var(--muted);
    white-space: nowrap;
  }
  @keyframes pipeline-pulse {
    0%, 100% { box-shadow: 0 0 0 0 rgba(201, 244, 59, 0.45); }
    50% { box-shadow: 0 0 0 4px rgba(201, 244, 59, 0.08); }
  }
  @media (max-width: 900px) {
    .pipeline { grid-template-columns: minmax(0, 1fr); gap: 12px; }
    .stage:not(:last-child)::after {
      top: auto;
      bottom: -12px;
      left: 30px;
      right: auto;
      width: 2px;
      height: 12px;
    }
    .pipeline-progress { grid-template-columns: minmax(0, 1fr); gap: 8px; }
    .pipeline-progress > span { white-space: normal; }
  }
</style>
