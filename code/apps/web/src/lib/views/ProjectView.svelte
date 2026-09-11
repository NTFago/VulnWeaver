<script lang="ts">
  import type { Artifact, ArtifactKind, ArtifactVersion, Project, Task } from "@vulnweaver/contracts";
  import { formatDate, shortId } from "../format";
  import { taskStatusLabels, taskResultLabels } from "../i18n";

  /** 项目详情页：样本导入、任务创建与最近任务列表。 */

  export let project: Project;
  export let artifacts: Artifact[] = [];
  export let artifactVersions = new Map<string, ArtifactVersion>();
  export let tasks: Task[] = [];
  export let busy = false;
  export let onGoOverview: () => void = () => {};
  export let onOpenTask: (task: Task) => void = () => {};
  export let onUpload: (kind: ArtifactKind, file: File) => Promise<boolean> = async () => false;
  export let onCreateTask: (versionIds: string[], tokenBudget: number) => Promise<boolean> = async () => false;
  export let onDeleteTask: (task: Task) => Promise<void> = async () => {};
  export let onShowError: (message: string) => void = () => {};

  let uploadKind: ArtifactKind = "source_archive";
  let uploadFile: File | null = null;
  let selectedVersionIds: string[] = [];
  let sampleListExpanded = false;
  let tokenBudget = 200_000;

  function confirmDeleteTask(task: Task): void {
    if (window.confirm(`确定删除该任务（${shortId(task.id)}）？其作业、Finding 与证据记录将被一并删除，且不可恢复。`)) {
      void onDeleteTask(task);
    }
  }
  const uploadAccept: Partial<Record<ArtifactKind, string>> = { source_archive: ".zip,.tar,.gz,.tgz,.bz2,.xz", pe: ".exe,.dll,.sys" };

  function versionFileName(versionId: string, versions: Map<string, ArtifactVersion>): string {
    return String(versions.get(versionId)?.generation_config.filename ?? "未命名样本");
  }

  function toggleVersion(versionId: string): void {
    selectedVersionIds = selectedVersionIds.includes(versionId)
      ? selectedVersionIds.filter((id) => id !== versionId) : [...selectedVersionIds, versionId];
  }

  async function upload(): Promise<void> {
    if (!uploadFile) {
      onShowError("请选择要导入的样本");
      return;
    }
    const uploaded = await onUpload(uploadKind, uploadFile);
    if (uploaded) {
      uploadFile = null;
      const input = document.querySelector<HTMLInputElement>("#sample-file");
      if (input) input.value = "";
    }
  }

  async function createTask(): Promise<void> {
    if (selectedVersionIds.length === 0) {
      onShowError("请至少选择一个样本");
      return;
    }
    const budget = Number.parseInt(String(tokenBudget), 10);
    if (!Number.isFinite(budget) || budget < 0) {
      onShowError("模型 Token 预算必须是不小于 0 的整数（0 表示不限制）");
      return;
    }
    await onCreateTask([...selectedVersionIds], budget);
  }
</script>

<section class="page-heading">
  <div>
    <button class="breadcrumb" disabled={busy} on:click={onGoOverview}>项目</button>
    <h1>{project.name}</h1>
    <p><code class="mono-id">{shortId(project.id)}</code>{project.input_scope.length > 0 ? ` · ${project.input_scope.join(" / ")}` : ""}</p>
  </div>
  <span class={`badge ${project.permission_mode === "request_permission" ? "warn" : "ok"}`}>{project.permission_mode === "request_permission" ? "动态执行需许可" : "授权范围内自动执行"}</span>
</section>
<section class="split-grid">
  <section class="panel">
    <header class="panel-head"><div><h2>导入样本</h2><p>原始工件不可变，登记后生成内容寻址版本。</p></div></header>
    <div class="upload-box">
      <label>样本类型<select bind:value={uploadKind}><option value="source_archive">源码压缩包</option><option value="elf">ELF 二进制</option><option value="pe">PE 二进制</option></select></label>
      <label class="file-picker" for="sample-file">
        <span>{uploadFile?.name ?? "选择本地样本"}</span>
        <small>{uploadFile ? `${(uploadFile.size / 1048576).toFixed(2)} MB` : "ZIP / TAR / ELF / PE"}</small>
      </label>
      <input id="sample-file" class="visually-hidden" type="file" accept={uploadAccept[uploadKind] ?? ""} on:change={(e) => uploadFile = e.currentTarget.files?.[0] ?? null} />
      <button class="primary block" on:click={upload} disabled={busy || !uploadFile}>导入工件库</button>
    </div>
  </section>
  <section class="panel">
    <header class="panel-head"><div><h2>创建任务</h2><p>选择一个或多个样本版本投递分析。</p></div></header>
    {#if artifacts.length === 0}
      <div class="compact-empty">导入样本后，可在此创建分析任务。</div>
    {:else}
      <div class="sample-options" class:expanded={sampleListExpanded}>
        {#each (sampleListExpanded ? artifacts : artifacts.slice(0, 3)) as artifact (artifact.id)}
          <label class:selected={selectedVersionIds.includes(artifact.current_version_id)} class="sample-option">
            <input type="checkbox" checked={selectedVersionIds.includes(artifact.current_version_id)} on:change={() => toggleVersion(artifact.current_version_id)} />
            <span><b>{versionFileName(artifact.current_version_id, artifactVersions)}</b><small>{artifact.kind === "source_archive" ? "源码压缩包" : artifact.kind === "source_repository" ? "源码仓库" : artifact.kind.toUpperCase()} · sha256:{artifactVersions.get(artifact.current_version_id)?.digest.slice(0, 12)}…</small></span>
          </label>
        {/each}
      </div>
      {#if artifacts.length > 3}
        <button class="sample-list-toggle" type="button" aria-expanded={sampleListExpanded} on:click={() => sampleListExpanded = !sampleListExpanded}>
          <span>{sampleListExpanded ? "收起样本" : `展开全部 ${artifacts.length} 个样本`}</span><small>已选 {selectedVersionIds.length} 个</small><span class="arrow" aria-hidden="true">⌄</span>
        </button>
      {/if}
      <label>模型 Token 预算
        <input type="number" min="0" step="1000" bind:value={tokenBudget} disabled={busy} />
        <small>智能体分析循环的模型 token 上限，填 0 表示不限制。</small>
      </label>
      <button class="primary block" on:click={createTask} disabled={busy || selectedVersionIds.length === 0}>投递分析任务{selectedVersionIds.length > 0 ? `（${selectedVersionIds.length}）` : ""}</button>
    {/if}
  </section>
</section>
<section class="panel table-panel">
  <header class="panel-head"><div><h2>最近任务</h2><p>点击进入执行轨迹。</p></div><span class="badge muted">{tasks.length} 条记录</span></header>
  {#if tasks.length === 0}
    <div class="compact-empty">暂无执行记录。</div>
  {:else}
    <div class="task-list">
      {#each tasks as task (task.id)}
        <div class="task-row">
          <button class="task-open" disabled={busy} on:click={() => onOpenTask(task)}>
            <span class={`status-dot ${task.status}`}></span>
            <span class="task-cell"><b>{task.result ? taskResultLabels[task.result] : taskStatusLabels[task.status]}</b><small>{shortId(task.id)} · {task.artifact_version_ids.length} 个输入</small></span>
            <time>{formatDate(task.updated_at)}</time>
            <span class="arrow" aria-hidden="true">→</span>
          </button>
          <button class="row-delete" title="删除任务" aria-label={`删除任务 ${shortId(task.id)}`} disabled={busy} on:click={() => confirmDeleteTask(task)}>✕</button>
        </div>
      {/each}
    </div>
  {/if}
</section>
