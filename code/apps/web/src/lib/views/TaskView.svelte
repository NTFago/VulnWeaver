<script lang="ts">
  import type {
    ArtifactVersion,
    Finding,
    FindingStatus,
    Job,
    PairFunction,
    Project,
    QueueEvent,
    Poc,
    Review,
    Task,
  } from "@vulnweaver/contracts";
  import type { AgentRun } from "@vulnweaver/contracts";
  import type { AuditTrail } from "../audit-trail";
  import type { FindingEvidenceDetail } from "../api";
  import { api } from "../api";
  import { formatDate } from "../format";
  import {
    confidenceTier,
    confidenceTierLabels,
    evidenceStrengthLabels,
    evidenceTypeLabels,
    failureCodeText,
    findingCategoryLabels,
    findingStatusLabels,
    jobKindLabels,
    jobStatusLabels,
    pocKindLabels,
    pocResultLabels,
    pocStatusLabels,
    severityLabels,
    taskResultLabels,
    taskStatusLabels,
  } from "../i18n";
  import ReportCenter from "../components/ReportCenter.svelte";
  import { pseudocodeText } from "../report-view";
  import TaskPipeline from "../components/TaskPipeline.svelte";
  import FindingStats from "../components/FindingStats.svelte";
  import AgentPanel from "../components/AgentPanel.svelte";
  import EventStream from "../components/EventStream.svelte";
  import type { PipelineTaskType } from "../pipeline";

  /** 任务详情页：任务状态、漏洞与报告、函数工作台、作业与事件轨迹、智能体运行。 */

  type PairNodeLike = { id: string; function_id: string | null };
  type PairEdgeLike = { source_node_id: string; target_node_id: string; type: string };

  export let task: Task;
  export let project: Project | null = null;
  export let jobs: Job[] = [];
  export let events: QueueEvent[] = [];
  export let findings: Finding[] = [];
  export let selectedFinding: Finding | null = null;
  export let evidence: FindingEvidenceDetail[] = [];
  export let pocs: Poc[] = [];
  export let reviews: Review[] = [];
  export let agentRuns: AgentRun[] = [];
  export let trail: AuditTrail | null = null;
  export let trailError = "";
  export let streamState: "connecting" | "connected" | "reconnecting" = "connecting";
  export let pairFunctions: PairFunction[] = [];
  export let pairNeighborhood: Record<string, unknown> | null = null;
  export let selectedFunctionId: string | null = null;
  export let reportVersionIds: string[] = [];
  export let artifactVersions = new Map<string, ArtifactVersion>();
  export let taskType: PipelineTaskType = "source";
  export let busy = false;

  export let onOpenProject: () => void = () => {};
  export let onRestartTask: () => void = () => {};
  export let onCancelTask: () => void = () => {};
  export let onCreateReport: (format: "markdown" | "pdf" | "sarif") => void = () => {};
  export let onCreateProof: (kind: "proof_of_concept" | "exploit", scriptRef: string, imageDigest: string) => void = () => {};
  export let onSelectFinding: (finding: Finding) => void = () => {};
  export let onSubmitReview: (outcome: FindingStatus, rationale: string) => Promise<boolean> = async () => false;
  export let onSubmitAnnotation: (note: string) => Promise<boolean> = async () => false;
  export let onSelectFunction: (fn: PairFunction) => void = () => {};

  let proofScriptRef = "";
  let proofImageDigest = "sha256:";
  let reviewOutcome: FindingStatus = "candidate";
  let reviewRationale = "";
  let annotationNote = "";
  let rightTab: "agents" | "events" | "jobs" = "agents";

  function functionLocation(fn: PairFunction): string {
    const source = fn.source_location;
    if (source) return `${source.path}:${source.start_line}`;
    const binary = fn.binary_location;
    if (binary) return `0x${binary.virtual_address.toString(16)}`;
    return fn.language;
  }

  type CriticalLogicEntry = {
    category: string;
    score: number;
    evidence: string[];
    confirmed: boolean | null;
    rationale: string | null;
  };

  function functionCritical(fn: PairFunction): CriticalLogicEntry[] {
    const value = (fn.attributes as Record<string, unknown> | undefined)?.critical_logic;
    return Array.isArray(value) ? (value as CriticalLogicEntry[]) : [];
  }

  function relatedFunctions(direction: "callers" | "callees"): PairFunction[] {
    if (!pairNeighborhood || !selectedFunctionId) return [];
    const nodes = (pairNeighborhood.nodes ?? []) as PairNodeLike[];
    const edges = (pairNeighborhood.edges ?? []) as PairEdgeLike[];
    const nodeFunction = new Map<string, string>();
    for (const node of nodes) if (node.function_id) nodeFunction.set(node.id, node.function_id);
    const byId = new Map(pairFunctions.map((fn) => [fn.id, fn]));
    const ids = new Set<string>();
    for (const edge of edges) {
      if (edge.type !== "call") continue;
      const source = nodeFunction.get(edge.source_node_id);
      const target = nodeFunction.get(edge.target_node_id);
      if (direction === "callees" && source === selectedFunctionId && target) ids.add(target);
      if (direction === "callers" && target === selectedFunctionId && source) ids.add(source);
    }
    ids.delete(selectedFunctionId);
    return [...ids].flatMap((id) => (byId.has(id) ? [byId.get(id) as PairFunction] : []));
  }

  function displayResult(result: Task["result"]): string {
    return result ? taskResultLabels[result] : "尚未生成";
  }

  function taskFailureContext(): string {
    if (!task.failure) return "";
    const reasons = task.failure.details.reason_codes;
    return [task.failure.code, task.failure.message, Array.isArray(reasons) ? reasons.join(", ") : ""]
      .filter(Boolean)
      .join(" · ");
  }

  function failureContext(job: Job): string {
    if (!job.failure) return "";
    const details = job.failure.details;
    const tool = typeof details.tool_name === "string" ? `工具：${details.tool_name}` : "";
    const reason = typeof details.reason === "string" ? `原因：${details.reason}` : "";
    const exitCode = typeof details.exit_code === "number" ? `退出码：${details.exit_code}` : "";
    return [tool, reason, exitCode].filter(Boolean).join(" · ");
  }

  $: failedJobs = jobs.filter((job) => job.status === "failed");
  $: confirmedFindings = findings.filter((finding) => finding.status === "confirmed").length;
  $: activeReportJobs = jobs.filter((job) => job.kind === "report" && ["pending", "queued", "running", "waiting_permission"].includes(job.status));
  $: reportStateText = reportVersionIds.length > 0
    ? `已生成 ${reportVersionIds.length} 份`
    : activeReportJobs.length > 0 ? "生成中" : "未生成";


  async function submitReview(): Promise<void> {
    if (!reviewRationale.trim()) return;
    const saved = await onSubmitReview(reviewOutcome, reviewRationale.trim());
    if (saved) reviewRationale = "";
  }

  async function submitAnnotation(): Promise<void> {
    if (!annotationNote.trim()) return;
    const saved = await onSubmitAnnotation(annotationNote.trim());
    if (saved) annotationNote = "";
  }

  function createProof(kind: "proof_of_concept" | "exploit"): void {
    onCreateProof(kind, proofScriptRef, proofImageDigest);
  }
</script>

<section class="page-heading task-heading">
  <div>
    <button class="breadcrumb" disabled={busy} on:click={onOpenProject}>{project?.name ?? "项目"}</button>
    <span class="task-kicker">{taskType === "source" ? "源码" : taskType === "binary" ? "二进制" : "混合样本"}审计工作台</span><h1>审计任务 · {task.id.split(":").pop()?.slice(0, 8)}</h1>
    {#if task.failure}<p class="task-failure">失败原因：{taskFailureContext()}</p>{/if}
    <p>结果：{displayResult(task.result)} · 更新于 {formatDate(task.updated_at)}</p>
  </div>
  <div class="task-actions">
    <span class={`status-badge large ${task.result === "partial" ? "waiting_permission" : task.status}`}><i></i>{task.result === "partial" ? "部分完成" : taskStatusLabels[task.status]}</span>
    {#if (failedJobs.length > 0 || ["completed", "failed", "cancelled"].includes(task.status))}<button class="secondary" on:click={onRestartTask} disabled={busy}>重新审计</button>{/if}
    {#if !["completed", "failed", "cancelled"].includes(task.status)}<button class="danger" on:click={onCancelTask} disabled={busy}>取消任务</button>{/if}
    <a class="secondary" href="#audit-reports">查看报告 <span aria-hidden="true">↓</span></a>
  </div>
</section>
<TaskPipeline {jobs} {taskType} {task} {project} />
{#if trail?.binary_analysis_jobs.length}
  <details class="panel binary-summary"><summary>二进制处理记录 · {trail.binary_analysis_jobs.length} 个执行单元</summary><p>识别、去壳、反编译与解混淆由二进制处理工具执行。以下仅展示已登记作业和产物，不将未暴露的子步骤标记为完成。</p>{#each trail.binary_analysis_jobs as item}<div><b>{jobStatusLabels[item.status]}</b> · 第 {item.attempt} 次尝试 · {item.output_version_ids.length} 份已登记产物<small>{item.job_id}</small>{#each item.output_version_ids as id}<code>{id}</code>{/each}</div>{/each}</details>
{/if}
<section class="metric-strip task-metrics" aria-label="任务统计">
  <div><strong>{findings.length}</strong><span>全部发现（含误报）</span></div>
  <div><strong>{confirmedFindings}</strong><span>已确认漏洞</span></div>
  <div><strong>{project?.exploit_validation_enabled ? "已开启" : "未开启"}</strong><span>自动动态深审</span></div>
  <div><strong>{reportStateText}</strong><span>报告状态</span></div>
</section>
<FindingStats {findings} />
<div class="task-columns">
  <div class="task-column">
    <section class="panel table-panel">
  <header class="panel-head">
    <div><h2>发现与证据</h2><p>查看候选依据，记录独立复核与人工判断。</p></div>
  </header>
  {#if findings.length === 0}
    <div class="compact-empty">当前任务尚未产生候选问题。</div>
  {:else}
    <div class="finding-list">
      {#each findings as finding (finding.id)}
        <button class:selected={selectedFinding?.id === finding.id} class="finding-row" on:click={() => onSelectFinding(finding)}>
          <span class={`status-dot ${finding.status}`}></span>
          <span class="task-cell"><b>{finding.title}</b><small>{severityLabels[finding.severity]} · {findingCategoryLabels[finding.category]} · {finding.cwe_id}</small></span>
          <span class="confidence" title="置信度：{confidenceTierLabels[confidenceTier(finding.confidence)]}">{Math.round(finding.confidence * 100)}%</span>
        </button>
      {/each}
    </div>
  {/if}
  {#if selectedFinding}
    <article class="finding-detail">
      <header><b>{selectedFinding.title}</b><span class={`status-dot ${selectedFinding.status}`}></span></header>
      <p>{selectedFinding.fix_suggestion}</p>
      <small>位置：{"path" in selectedFinding.location ? `${selectedFinding.location.path}:${selectedFinding.location.start_line}` : `0x${selectedFinding.location.virtual_address.toString(16)}`} · 证据：{selectedFinding.evidence_ids.length} 条 · 复现记录：{selectedFinding.poc_ids.length} 条</small>
      <div class="proof-actions">
        <label>脚本引用<input bind:value={proofScriptRef} placeholder="CAS 对象引用" /></label>
        <label>镜像摘要<input bind:value={proofImageDigest} placeholder="sha256:..." /></label>
        <button class="secondary" on:click={() => createProof("proof_of_concept")} disabled={busy}>发起概念验证</button>
        {#if selectedFinding.status === "confirmed" && project?.exploit_validation_enabled}<button class="danger" on:click={() => createProof("exploit")} disabled={busy}>发起利用验证</button>{/if}
      </div>
      <div class="proof-actions review-actions">
        <label>复核结论<select bind:value={reviewOutcome}><option value="candidate">候选</option><option value="confirmed">确认</option><option value="false_positive">误报</option><option value="disputed">有争议</option><option value="unverifiable">无法验证</option></select></label>
        <label>人工复核意见<textarea bind:value={reviewRationale} rows="2" placeholder="记录复核结论与依据"></textarea></label>
        <button class="secondary" on:click={submitReview} disabled={busy || !reviewRationale.trim()}>保存复核</button>
      </div>
      <div class="proof-actions annotation-actions">
        <label>标注<textarea bind:value={annotationNote} rows="2" placeholder="记录问题标签或修正说明"></textarea></label>
        <button class="secondary" on:click={submitAnnotation} disabled={busy || !annotationNote.trim()}>保存标注</button>
      </div>
      {#if reviews.length > 0}
        <div class="detail-evidence"><b>复核历史</b>{#each reviews as review, i (i)}<small>{findingStatusLabels[review.outcome]} · {review.model} · {review.rationale}</small>{/each}</div>
      {/if}
      {#if evidence.length > 0}
        <div class="detail-evidence"><b>证据链</b>{#each evidence as item, i (i)}<small>{evidenceTypeLabels[item.evidence.type]} · {evidenceStrengthLabels[item.evidence.strength]} · {item.evidence.tool?.name ?? "人工"} · {item.evidence.digest.slice(0, 16)}…</small>{/each}</div>
      {/if}
      {#if pocs.length > 0}
        <div class="detail-evidence"><b>复现记录</b>{#each pocs as poc (poc.id)}<small>{pocKindLabels[poc.kind]} · {pocStatusLabels[poc.status]} · {poc.result ? pocResultLabels[poc.result] : "未执行"}</small>{/each}</div>
      {/if}
    </article>
  {/if}
    </section>
  </div>
  <div class="task-column">
    <section class="panel table-panel">
      <header class="panel-head">
        <div class="tabs" aria-label="任务详情面板">
          <button class:active={rightTab === "agents"} aria-pressed={rightTab === "agents"} on:click={() => (rightTab = "agents")}>智能体协作</button>
          <button class:active={rightTab === "events"} aria-pressed={rightTab === "events"} on:click={() => (rightTab = "events")}>事件流</button>
          <button class:active={rightTab === "jobs"} aria-pressed={rightTab === "jobs"} on:click={() => (rightTab = "jobs")}>作业列表</button>
        </div>
      </header>
      {#if rightTab === "agents"}
        <AgentPanel {agentRuns} {trail} {trailError} />
      {:else if rightTab === "events"}
        <p class="stream-state">{streamState === "connected" ? "事件连接正常" : streamState === "reconnecting" ? "连接恢复中；已接收事件保留，任务数据定时刷新" : "正在连接事件流"}</p><EventStream {events} {jobs} />
      {:else}
        {#if jobs.length === 0}
          <div class="compact-empty">等待编排服务消费 <code>task.requested</code>。</div>
        {:else}
          <div class="job-list">
            {#each jobs as job (job.id)}
              <article>
                <span class={`status-dot ${job.status}`}></span>
                <div><b>{jobKindLabels[job.kind]}</b><small>{jobStatusLabels[job.status]} · 第 {job.attempt}/{job.retry_policy.max_attempts} 次尝试</small></div>
                {#if job.status === "failed"}<small>原执行记录已保留；可在页面顶部重新审计。</small>{/if}
                {#if job.failure}<p>{job.failure.message}</p><small>{failureCodeText(job.failure.code)}{failureContext(job) ? ` · ${failureContext(job)}` : ""}</small>{/if}
              </article>
            {/each}
          </div>
        {/if}
      {/if}
    </section>
  </div>
</div>
<section class="panel table-panel">
  <header class="panel-head"><div><h2>函数与调用链</h2><p>点击函数联动调用关系与伪代码。</p></div></header>
  {#if pairFunctions.length === 0}
    <div class="compact-empty">样本索引完成后，此处将列出函数、伪代码与调用链。</div>
  {:else}
    <div class="workbench">
      <div class="function-list" role="listbox" aria-label="函数列表">
        {#each pairFunctions as fn (fn.id)}
          <button class:selected={selectedFunctionId === fn.id} on:click={() => onSelectFunction(fn)}>
            <b>{fn.name}</b>
            {#if functionCritical(fn).length > 0}<em class="key-badge">{functionCritical(fn).map((entry) => entry.category).join(" / ")}</em>{/if}
            <small>{functionLocation(fn)}</small>
          </button>
        {/each}
      </div>
      <div class="function-detail">
        {#if !selectedFunctionId}
          <div class="compact-empty">选择一个函数，查看其调用方、被调用方与伪代码。</div>
        {:else}
          {@const selected = pairFunctions.find((fn) => fn.id === selectedFunctionId)}
          {#if selected}
            <div class="function-title-block"><b class="function-title">{selected.name}</b><small>{selected.signature ?? functionLocation(selected)}</small></div>
            {#if pseudocodeText(selected)}<pre class="code-view">{pseudocodeText(selected)}</pre>{:else}<small class="muted">该函数没有已导出的伪代码。</small>{/if}
            {#if pairNeighborhood}
              <div class="call-columns">
                <div><b>调用方</b>{#each relatedFunctions("callers") as caller (caller.id)}<button on:click={() => onSelectFunction(caller)}>{caller.name}</button>{:else}<small class="muted">无</small>{/each}</div>
                <div><b>被调用</b>{#each relatedFunctions("callees") as callee (callee.id)}<button on:click={() => onSelectFunction(callee)}>{callee.name}</button>{:else}<small class="muted">无</small>{/each}</div>
              </div>
            {:else}<small class="muted">调用关系加载中…</small>{/if}
          {/if}
        {/if}
      </div>
    </div>
  {/if}
</section>

<ReportCenter {jobs} versions={reportVersionIds.flatMap(id => artifactVersions.has(id) ? [artifactVersions.get(id)!] : [])} {busy} onGenerate={onCreateReport} />

<style>
  .binary-summary { margin: 0 0 24px; font-size: 13px; }
  .binary-summary summary { cursor: pointer; color: var(--text-2); }
  .binary-summary p, .binary-summary small { color: var(--muted); font-size: 12px; }
  .binary-summary small, .binary-summary code { display: block; overflow-wrap: anywhere; }
  .stream-state { color: var(--muted); font-size: 12px; margin: 12px 0 0; }
  .task-kicker { display: block; color: var(--accent); font-size: 12px; margin: 8px 0; letter-spacing: .08em; }
  .task-columns {
    display: grid;
    grid-template-columns: minmax(0, 1fr);
    gap: 24px;
    margin-top: 0;
    align-items: start;
  }
  .task-column { min-width: 0; display: grid; }
  .task-column > .table-panel { margin-top: 0; }
  @media (min-width: 1180px) {
    .task-columns { grid-template-columns: minmax(0, 1.05fr) minmax(0, 0.95fr); }
  }
  .tabs { display: flex; gap: 6px; flex-wrap: wrap; }
  .tabs button {
    border: 1px solid transparent;
    border-radius: var(--radius-s);
    background: transparent;
    color: var(--muted);
    padding: 8px 13px;
    font-size: 13.5px;
    font-weight: 600;
    display: inline-flex;
    align-items: center;
    gap: 8px;
    transition: color 0.16s var(--ease), background 0.16s var(--ease), border-color 0.16s var(--ease);
  }
  .tabs button:hover { color: var(--text); background: var(--panel-2); }
  .tabs button.active {
    color: var(--accent);
    background: rgba(201, 244, 59, 0.08);
    border-color: rgba(201, 244, 59, 0.35);
  }
</style>
