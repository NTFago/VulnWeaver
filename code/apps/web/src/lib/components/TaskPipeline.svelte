<script lang="ts">
  import type { Job, Project, Task } from "@vulnweaver/contracts";
  import { aggregatePipelineStages, pipelineProgress, stageStatusLabels, type PipelineTaskType } from "../pipeline";
  export let jobs: Job[] = [];
  export let taskType: PipelineTaskType = "source";
  export let task: Task;
  export let project: Project | null = null;
  $: stages = aggregatePipelineStages(jobs, taskType, task, project);
  $: progress = pipelineProgress(stages);
</script>

<section class="pipeline-panel" aria-label="审计执行概况">
  <header class="pipeline-header">
    <div><span class="eyebrow">审计过程</span><h2>从样本到证据，每一步都有记录</h2><p>{progress.activeNames.length ? `当前：${progress.activeNames.join("、")}` : ["completed", "failed", "cancelled"].includes(task.status) ? "本轮执行已结束，请结合任务结果查看未完成项。" : "等待编排服务调度下一步。"}</p></div>
    <div class="progress-summary"><strong>{progress.settled}<em> / {progress.total}</em></strong><span>已结束的执行单元</span><small>成功 {progress.succeeded} · 失败 {progress.failed}</small></div>
  </header>
  <div class="execution-track" role="progressbar" aria-label="已调度执行单元结束比例" aria-valuemin="0" aria-valuemax="100" aria-valuenow={progress.percent} aria-valuetext={`${progress.settled}/${progress.total} 执行单元已结束`}><i class:has-failure={progress.failed > 0} style={`width:${progress.percent}%`}></i></div>
  <ol class="stage-grid">
    {#each stages as stage, index (stage.key)}
      <li class={`stage ${stage.status}`}>
        <div class="stage-top"><span class="stage-index">{String(index + 1).padStart(2, "0")}</span><span class="stage-state">{stageStatusLabels[stage.status]}</span></div>
        <h3>{stage.name}</h3><p>{stage.description}</p>
        <small>{stage.total ? `${stage.done}/${stage.total} 执行单元成功` : stage.status === "skipped" ? "项目未开启自动动态深审" : "尚无执行记录"}</small>
        {#if stage.failureText}<details class="stage-error"><summary>查看失败原因</summary><p>{stage.failureText}</p></details>{/if}
      </li>
    {/each}
  </ol>
  <p class="pipeline-note">进度按当前已调度的执行单元计算，后续调度会增加总数；不代表代码覆盖率或漏洞确认程度。</p>
</section>

<style>
  .pipeline-panel { padding: 26px; border: 1px solid var(--line-strong); border-radius: var(--radius-m); background: linear-gradient(125deg, #202819 0%, var(--panel) 58%); margin-bottom: 24px; }
  .pipeline-header { display: flex; justify-content: space-between; gap: 24px; align-items: start; }
  .eyebrow { font-size: 12px; color: var(--accent); letter-spacing: .12em; }
  h2 { font-size: 22px; margin: 8px 0; font-weight: 600; }
  .pipeline-header p { color: var(--text-2); font-size: 13px; margin: 0; }
  .progress-summary { text-align: right; display: grid; gap: 3px; flex: 0 0 auto; }
  .progress-summary strong { font: 500 34px/1.2 var(--font-mono); }
  .progress-summary em { font-size: 18px; color: var(--muted); font-style: normal; }
  .progress-summary span, .progress-summary small { font-size: 12px; color: var(--muted); }
  .execution-track { height: 4px; border-radius: 9px; background: var(--line); margin: 23px 0; overflow: hidden; }
  .execution-track i { display: block; height: 100%; background: var(--accent); transition: width .25s; }
  .execution-track i.has-failure { background: var(--warn); }
  .stage-grid { list-style: none; display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); padding: 0; gap: 12px; margin: 0; }
  .stage { border: 1px solid var(--line); border-radius: 8px; background: var(--panel); padding: 15px; min-width: 0; }
  .stage.running, .stage.waiting_permission { border-color: var(--accent); background: #252d1b; }
  .stage.failed, .stage.partial { border-color: #764b3d; }
  .stage-top { display: flex; justify-content: space-between; gap: 8px; color: var(--muted); font-size: 12px; }
  .stage-index { font-family: var(--font-mono); }
  .running .stage-state { color: var(--accent); }
  .waiting_permission .stage-state, .partial .stage-state { color: var(--warn); }
  .succeeded .stage-state { color: var(--ok); }
  .failed .stage-state { color: var(--danger); }
  h3 { font-size: 15px; margin: 11px 0 7px; }
  .stage p { font-size: 12px; color: var(--muted); margin: 0 0 12px; line-height: 1.65; }
  .stage small { color: var(--text-2); font-size: 12px; }
  .stage-error { color: var(--danger); margin-top: 10px; font-size: 12px; overflow-wrap: anywhere; }
  .pipeline-note { font-size: 12px; color: var(--muted); margin: 16px 0 0; }
  @media (min-width: 1550px) { .stage-grid { grid-template-columns: repeat(7, minmax(0, 1fr)); } }
  @media (max-width: 760px) { .stage-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); } .pipeline-panel { padding: 18px; } h2 { font-size: 19px; } .pipeline-header { flex-direction: column; gap: 16px; } .progress-summary { text-align: left; } }
  @media (max-width: 400px) { .stage-grid { grid-template-columns: minmax(0, 1fr); } }
  @media (prefers-reduced-motion: reduce) { .execution-track i { transition: none; } }
</style>
