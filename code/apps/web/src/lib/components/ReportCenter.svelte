<script lang="ts">
  import type { ArtifactVersion, Job } from "@vulnweaver/contracts";
  import { api } from "../api";
  import { jobStatusLabels } from "../i18n";
  import { formatDate } from "../format";
  import { reportFormats, reportLabels, reportView, type ReportFormat } from "../report-view";
  export let jobs: Job[] = [];
  export let versions: ArtifactVersion[] = [];
  export let busy = false;
  export let onGenerate: (format: ReportFormat) => void = () => {};
</script>

<section class="panel report-center" id="audit-reports" aria-label="审计报告中心">
  <header class="panel-head"><div><span class="eyebrow">审计交付</span><h2>报告与结果导出</h2><p>保留扫描事实、证据链与复核记录，按用途选择格式。</p></div><span class="badge muted">{versions.length} 份已登记</span></header>
  <div class="report-grid">
    {#each reportFormats as format}
      {@const label = reportLabels[format]}
      {@const view = reportView(format, jobs, versions)}
      <article class="report-card" class:featured={format === "pdf"}>
        <span class="format-mark">{format === "markdown" ? "MD" : format.toUpperCase()}</span>
        <h3>{label.name}</h3><p>{label.description}</p>
        <div class="report-states" aria-live="polite">
          {#each view.jobs as job (job.id)}
            <span class:failed={job.status === "failed"}>{jobStatusLabels[job.status]}</span>
            {#if job.failure}<details class="report-error"><summary>生成失败详情</summary><p>{job.failure.message}</p><code>{job.failure.code}</code><p>此执行记录已保留；可重新审计生成新的任务报告。</p></details>{/if}
          {:else}<span>尚未生成</span>{/each}
        </div>
        <div class="report-downloads">
          {#each view.versions as version (version.id)}
            <a class="secondary" href={api.artifactContentUrl(version.artifact_id, version.id)} download={`vulnweaver-report.${label.extension}`}>下载 {format === "markdown" ? "Markdown" : format.toUpperCase()} <span aria-hidden="true">↓</span></a>
            <small>生成于 {formatDate(version.created_at)}</small>
          {/each}
          {#if !view.versions.length && !view.jobs.some(job => ["failed", "cancelled", "succeeded"].includes(job.status))}
            <button class={format === "pdf" ? "primary" : "secondary"} disabled={busy || view.active} on:click={() => onGenerate(format)}>{view.active ? "等待生成完成" : "生成报告"}</button>
          {/if}
          {#if !view.versions.length && view.jobs.some(job => job.status === "succeeded")}<small>执行已完成，报告文件正在加载。</small>{/if}
        </div>
      </article>
    {/each}
  </div>
  <p class="report-footnote">已生成文件保留生成时的结论。后续复核可能改变当前发现状态；下载已有文件不会重新生成报告。</p>
</section>

<style>
  .report-center { margin-top: 24px; }
  .eyebrow { color: var(--accent); font-size: 12px; letter-spacing: .08em; }
  .report-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 16px; margin-top: 22px; }
  .report-card { display: flex; flex-direction: column; align-items: start; border: 1px solid var(--line); background: var(--panel-2); border-radius: var(--radius-s); padding: 22px; min-width: 0; }
  .report-card.featured { border-color: #546334; background: linear-gradient(130deg, #28311d, var(--panel-2)); }
  .format-mark { font: 600 12px/1 var(--font-mono); color: var(--accent); border: 1px solid #485331; padding: 9px 11px; border-radius: 6px; }
  h3 { margin: 18px 0 5px; font-size: 17px; }
  p { color: var(--muted); font-size: 12px; margin: 0 0 16px; }
  .report-states { display: grid; gap: 8px; margin-bottom: 18px; font-size: 12px; color: var(--text-2); }
  .failed, .report-error { color: var(--danger); }
  .report-error { overflow-wrap: anywhere; }
  .report-error p { margin: 8px 0; }
  .report-downloads { display: grid; gap: 9px; margin-top: auto; width: 100%; }
  .report-downloads a { text-align: center; display: flex; justify-content: space-between; }
  .report-downloads small { font-size: 11px; color: var(--muted); }
  .report-footnote { margin: 18px 0 0; }
  @media (max-width: 850px) { .report-grid { grid-template-columns: minmax(0, 1fr); } }
</style>
