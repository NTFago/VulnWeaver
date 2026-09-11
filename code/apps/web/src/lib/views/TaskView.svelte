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
  export let pairFunctions: PairFunction[] = [];
  export let pairNeighborhood: Record<string, unknown> | null = null;
  export let selectedFunctionId: string | null = null;
  export let reportVersionIds: string[] = [];
  export let artifactVersions = new Map<string, ArtifactVersion>();
  export let taskType: PipelineTaskType = "source";
  export let busy = false;

  export let onOpenProject: () => void = () => {};
  export let onRetryJobs: (jobIds: string[]) => Promise<boolean> = async () => false;
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

  function functionPseudocode(fn: PairFunction): string | null {
    const value = (fn.attributes as Record<string, unknown> | undefined)?.pseudocode;
    if (typeof value === "string" && value.trim()) return value;
    return null;
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

  function reportJobs(): Job[] {
    return jobs.filter((job) => job.kind === "report");
  }

  function reportStatusText(job: Job): string {
    const format = typeof job.arguments?.format === "string" ? job.arguments.format.toUpperCase() : "报告";
    if (job.status === "failed") {
      const reason = job.failure?.message ?? "未返回具体原因";
      return `${format} 报告生成失败：${reason}${job.failure?.code ? `（${job.failure.code}）` : ""}`;
    }
    if (job.status === "succeeded") return `${format} 报告已生成`;
    return `${format} 报告生成中…`;
  }

  function reportFileName(versionId: string): string {
    const format = artifactVersions.get(versionId)?.generation_config.format;
    if (format === "pdf") return "vulnweaver-report.pdf";
    if (format === "sarif") return "vulnweaver-report.sarif";
    return "vulnweaver-report.md";
  }

  $: failedJobs = jobs.filter((job) => job.status === "failed");
  $: confirmedFindings = findings.filter((finding) => finding.status === "confirmed").length;
  $: activeReportJobs = jobs.filter((job) => job.kind === "report" && ["pending", "queued", "running", "waiting_permission"].includes(job.status));
  $: reportStateText = reportVersionIds.length > 0
    ? `已生成 ${reportVersionIds.length} 份`
    : activeReportJobs.length > 0 ? "生成中" : "未生成";

  function retryFailedJobs(): void {
    void onRetryJobs(failedJobs.map((job) => job.id));
  }

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
    <button class="breadcrumb" on:click={onOpenProject}>{project?.name ?? "项目"}</button>
    <h1>{taskStatusLabels[task.status]}</h1>
    {#if task.failure}<p class="task-failure">失败原因：{taskFailureContext()}</p>{/if}
    <p>结果：{displayResult(task.result)} · 更新于 {formatDate(task.updated_at)}</p>
  </div>
  <div class="task-actions">
    <span class={`status-badge large ${task.status}`}><i></i>{taskStatusLabels[task.status]}</span>
    {#if failedJobs.length > 0}<button class="secondary" on:click={retryFailedJobs} disabled={busy}>重试失败作业（{failedJobs.length}）</button>{/if}
    {#if !["completed", "failed", "cancelled"].includes(task.status)}<button class="danger" on:click={onCancelTask} disabled={busy}>取消任务</button>{/if}
    <button class="secondary" on:click={() => onCreateReport("markdown")} disabled={busy}>报告 Markdown</button>
    <button class="secondary" on:click={() => onCreateReport("sarif")} disabled={busy}>报告 SARIF</button>
    <button class="secondary" on:click={() => onCreateReport("pdf")} disabled={busy}>报告 PDF</button>
  </div>
</section>
<TaskPipeline {jobs} {taskType} taskStatus={task?.status} {busy} onRetryStage={(jobIds) => void onRetryJobs(jobIds)} />
<section class="metric-strip task-metrics" aria-label="任务统计">
  <div><strong>{findings.length}</strong><span>漏洞总数</span></div>
  <div><strong>{confirmedFindings}</strong><span>已确认漏洞</span></div>
  <div><strong>{failedJobs.length}</strong><span>失败作业</span></div>
  <div><strong>{reportStateText}</strong><span>报告状态</span></div>
</section>
<FindingStats {findings} />
<div class="task-columns">
  <div class="task-column">
    <section class="panel table-panel">
  <header class="panel-head">
    <div><h2>问题与报告</h2><p>候选问题、人工复核与报告导出。</p></div>
  </header>
  {#if findings.length === 0}
    <div class="compact-empty">当前任务尚未产生候选问题。</div>
  {:else}
    <div class="finding-list">
      {#each findings as finding (finding.id)}
        <button class="finding-row" on:click={() => onSelectFinding(finding)}>
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
      <small>位置：{JSON.stringify(selectedFinding.location)} · 证据：{selectedFinding.evidence_ids.length} 条 · 复现记录：{selectedFinding.poc_ids.length} 条</small>
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
  {#if reportJobs().length > 0}
    <div class="report-statuses" aria-live="polite">
      {#each reportJobs() as reportJob (reportJob.id)}
        <small class:failed={reportJob.status === "failed"}>{reportStatusText(reportJob)}</small>
      {/each}
    </div>
  {/if}
  {#if reportVersionIds.length > 0}
    <div class="report-links">
      {#each reportVersionIds as versionId (versionId)}
        {#if artifactVersions.get(versionId)}<a class="secondary" href={api.artifactContentUrl(artifactVersions.get(versionId)!.artifact_id, versionId)} download={reportFileName(versionId)}>下载报告 · {artifactVersions.get(versionId)!.generation_config.format ?? "文件"}</a>{/if}
      {/each}
    </div>
  {/if}
    </section>
  </div>
  <div class="task-column">
    <section class="panel table-panel">
      <header class="panel-head">
        <div class="tabs" aria-label="任务详情面板">
          <button class:active={rightTab === "agents"} aria-pressed={rightTab === "agents"} on:click={() => (rightTab = "agents")}>智能体协作</button>
          <button class:active={rightTab === "events"} aria-pressed={rightTab === "events"} on:click={() => (rightTab = "events")}>事件流<span class="live"><i></i>实时</span></button>
          <button class:active={rightTab === "jobs"} aria-pressed={rightTab === "jobs"} on:click={() => (rightTab = "jobs")}>作业列表</button>
        </div>
      </header>
      {#if rightTab === "agents"}
        <AgentPanel {agentRuns} />
      {:else if rightTab === "events"}
        <EventStream {events} {jobs} />
      {:else}
        {#if jobs.length === 0}
          <div class="compact-empty">等待编排服务消费 <code>task.requested</code>。</div>
        {:else}
          <div class="job-list">
            {#each jobs as job (job.id)}
              <article>
                <span class={`status-dot ${job.status}`}></span>
                <div><b>{jobKindLabels[job.kind]}</b><small>{jobStatusLabels[job.status]} · 第 {job.attempt}/{job.retry_policy.max_attempts} 次尝试</small></div>
                {#if job.status === "failed"}<button class="text-button job-retry" disabled={busy} on:click={() => void onRetryJobs([job.id])}>重试</button>{/if}
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
            {#if functionPseudocode(selected)}<pre class="code-view">{functionPseudocode(selected)}</pre>{:else}<small class="muted">该函数没有已导出的伪代码。</small>{/if}
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

<style>
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
  .tabs .live { font-size: 10px; }
  .job-retry { grid-column: 2; justify-self: start; color: var(--warn); padding: 2px 8px; }
  .job-retry:hover { color: var(--text); }
</style>
