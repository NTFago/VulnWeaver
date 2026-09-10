<script lang="ts">
  import type { Finding, FindingStatus, Severity } from "@vulnweaver/contracts";
  import { findingStatusLabels, severityLabels } from "../i18n";

  /** 漏洞统计：按严重等级（横向条形）与确认状态（计数徽章）汇总。 */

  export let findings: Finding[] = [];

  const severityOrder: Severity[] = ["critical", "high", "medium", "low", "info"];
  const statusOrder: FindingStatus[] = ["confirmed", "candidate", "false_positive", "disputed", "unverifiable"];
  const statusBadgeClass: Record<FindingStatus, string> = {
    confirmed: "ok",
    candidate: "accent",
    false_positive: "muted",
    disputed: "warn",
    unverifiable: "muted",
  };

  $: total = findings.length;
  $: maxSeverityCount = Math.max(1, ...severityOrder.map((sev) => findings.filter((finding) => finding.severity === sev).length));
  $: severityRows = severityOrder.map((sev) => {
    const count = findings.filter((finding) => finding.severity === sev).length;
    return { key: sev, label: severityLabels[sev], count, percent: Math.round((count / maxSeverityCount) * 100) };
  });
  $: statusRows = statusOrder.map((status) => ({
    key: status,
    label: findingStatusLabels[status],
    count: findings.filter((finding) => finding.status === status).length,
    badge: statusBadgeClass[status],
  }));
</script>

<section class="panel finding-stats" aria-label="漏洞统计">
  <header class="panel-head">
    <div><h2>漏洞统计</h2><p>按严重等级与确认状态汇总，随任务事件实时更新。</p></div>
    <span class="badge accent">共 {total} 个</span>
  </header>
  <div class="stats-body">
    <div class="severity-bars">
      {#each severityRows as row (row.key)}
        <div class="sev-row" class:zero={row.count === 0}>
          <span class="sev-label">{row.label}</span>
          <span class="sev-track"><i class={row.key} style={`width: ${row.percent}%`}></i></span>
          <span class="sev-count">{row.count}</span>
        </div>
      {/each}
    </div>
    <div class="status-badges">
      {#each statusRows as row (row.key)}
        <span class={`badge ${row.badge}`}>{row.label} {row.count}</span>
      {/each}
    </div>
  </div>
</section>

<style>
  .finding-stats { margin-bottom: 24px; }
  .stats-body {
    display: grid;
    grid-template-columns: minmax(0, 1.4fr) minmax(0, 1fr);
    gap: 26px;
    margin-top: 18px;
    align-items: start;
  }
  .severity-bars { display: grid; gap: 9px; }
  .sev-row {
    display: grid;
    grid-template-columns: 44px minmax(0, 1fr) 34px;
    gap: 12px;
    align-items: center;
  }
  .sev-row.zero { opacity: 0.55; }
  .sev-label { font-size: 12.5px; color: var(--text-2); white-space: nowrap; }
  .sev-track {
    display: block;
    height: 10px;
    border-radius: 999px;
    background: var(--field);
    border: 1px solid var(--line);
    overflow: hidden;
  }
  .sev-track i { display: block; height: 100%; border-radius: 999px; transition: width 0.3s var(--ease); }
  .sev-track i.critical { background: var(--danger); }
  .sev-track i.high { background: #f0883e; }
  .sev-track i.medium { background: var(--warn); }
  .sev-track i.low { background: #6fc3df; }
  .sev-track i.info { background: #6f766c; }
  .sev-count {
    font: 600 12.5px/1 var(--font-mono);
    color: var(--text-2);
    text-align: right;
    font-variant-numeric: tabular-nums;
  }
  .status-badges { display: flex; flex-wrap: wrap; gap: 10px; align-content: start; }
  @media (max-width: 900px) {
    .stats-body { grid-template-columns: minmax(0, 1fr); gap: 18px; }
  }
</style>
