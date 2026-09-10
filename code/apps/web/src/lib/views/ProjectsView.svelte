<script context="module" lang="ts">
  import type { PermissionMode, ResourceBudget } from "@vulnweaver/contracts";

  export interface NewProjectPayload {
    name: string;
    input_scope: string[];
    permission_mode: PermissionMode;
    exploit_validation_enabled: boolean;
    resource_budget?: ResourceBudget;
  }
</script>

<script lang="ts">
  import type { Project } from "@vulnweaver/contracts";
  import { formatDate } from "../format";

  /** 项目总览页：项目统计、创建项目表单与项目列表。 */

  export let projects: Project[] = [];
  export let busy = false;
  export let onOpenProject: (project: Project) => void = () => {};
  export let onCreateProject: (payload: NewProjectPayload) => Promise<boolean> = async () => false;
  export let onShowError: (message: string) => void = () => {};

  type BudgetInputs = {
    max_model_tokens: string;
    cpu_millis: string;
    memory_bytes: string;
    disk_bytes: string;
    max_tool_concurrency: string;
    max_dynamic_runs: string;
    timeout_seconds: string;
  };
  const blankBudgetInputs = (): BudgetInputs => ({
    max_model_tokens: "", cpu_millis: "", memory_bytes: "", disk_bytes: "",
    max_tool_concurrency: "", max_dynamic_runs: "", timeout_seconds: "",
  });
  const budgetLabels: Record<keyof BudgetInputs, string> = {
    cpu_millis: "CPU（毫核）",
    memory_bytes: "内存（字节）",
    disk_bytes: "磁盘（字节）",
    timeout_seconds: "超时（秒）",
    max_model_tokens: "模型 token 上限",
    max_tool_concurrency: "并发工具数",
    max_dynamic_runs: "动态运行额度",
  };

  let showProjectForm = false;
  let projectName = "";
  let projectScope = "已授权本地样本";
  let permissionMode: PermissionMode = "request_permission";
  let exploitEnabled = false;
  let customBudget = false;
  let budgetInputs: BudgetInputs = blankBudgetInputs();

  function budgetFromForm(): ResourceBudget | undefined {
    if (!customBudget) return undefined;
    const parsed: Record<string, number> = {};
    for (const key of Object.keys(budgetInputs) as (keyof BudgetInputs)[]) {
      const value = Number(budgetInputs[key].trim());
      if (!Number.isInteger(value) || value < 0) {
        throw new Error(`资源预算「${budgetLabels[key]}」必须是不小于 0 的整数`);
      }
      parsed[key] = value;
    }
    return parsed as unknown as ResourceBudget;
  }

  async function createProject(): Promise<void> {
    if (!projectName.trim()) {
      onShowError("请输入项目名称");
      return;
    }
    let budget: ResourceBudget | undefined;
    try {
      budget = budgetFromForm();
    } catch (caught) {
      onShowError(caught instanceof Error ? caught.message : "资源预算填写不正确");
      return;
    }
    const created = await onCreateProject({
      name: projectName.trim(),
      input_scope: [projectScope.trim()],
      permission_mode: permissionMode,
      exploit_validation_enabled: exploitEnabled,
      resource_budget: budget,
    });
    if (created) {
      showProjectForm = false;
      projectName = "";
      customBudget = false;
      budgetInputs = blankBudgetInputs();
    }
  }
</script>

<section class="page-heading">
  <div><h1>项目与分析范围</h1><p>每个项目隔离样本、任务和证据链，运行前明确授权边界。</p></div>
  <button class="primary" on:click={() => showProjectForm = !showProjectForm}>{showProjectForm ? "收起表单" : "新建项目"}</button>
</section>
<section class="metric-strip" aria-label="项目统计">
  <div><strong>{projects.length}</strong><span>已授权项目</span></div>
  <div><strong>{projects.filter((p) => p.exploit_validation_enabled).length}</strong><span>开启利用验证</span></div>
  <div><strong>{projects.filter((p) => p.permission_mode === "request_permission").length}</strong><span>需运行许可</span></div>
</section>
{#if showProjectForm}
  <form class="panel project-form" on:submit|preventDefault={createProject}>
    <header class="panel-head"><div><h2>创建项目</h2><p>为一次分析定义授权范围与运行模式。</p></div></header>
    <div class="field-grid">
      <label>项目名称<input bind:value={projectName} placeholder="例：网关 2.4 安全复核" required /></label>
      <label>授权范围<input bind:value={projectScope} required /></label>
      <label>运行模式<select bind:value={permissionMode}><option value="request_permission">每次动态执行前请求许可</option><option value="full_access">在已授权范围内自动执行</option></select></label>
    </div>
    <label class="check"><input type="checkbox" bind:checked={exploitEnabled} /><span><b>允许利用验证</b><small>仅对 confirmed Finding，且仍需经策略门禁。</small></span></label>
    <label class="check"><input type="checkbox" bind:checked={customBudget} /><span><b>自定义资源预算</b><small>不勾选则使用覆盖全部已注册工具的默认预算；低于工具要求的预算会被拒绝。</small></span></label>
    {#if customBudget}
      <div class="field-grid cols-4">
        <label>CPU（毫核）<input type="text" inputmode="numeric" bind:value={budgetInputs.cpu_millis} required /></label>
        <label>内存（字节）<input type="text" inputmode="numeric" bind:value={budgetInputs.memory_bytes} required /></label>
        <label>磁盘（字节）<input type="text" inputmode="numeric" bind:value={budgetInputs.disk_bytes} required /></label>
        <label>超时（秒）<input type="text" inputmode="numeric" bind:value={budgetInputs.timeout_seconds} required /></label>
        <label>模型 token 上限<input type="text" inputmode="numeric" bind:value={budgetInputs.max_model_tokens} required /></label>
        <label>并发工具数<input type="text" inputmode="numeric" bind:value={budgetInputs.max_tool_concurrency} required /></label>
        <label>动态运行额度<input type="text" inputmode="numeric" bind:value={budgetInputs.max_dynamic_runs} required /></label>
      </div>
    {/if}
    <div class="form-actions"><button class="primary" disabled={busy}>创建并进入</button></div>
  </form>
{/if}
{#if projects.length === 0}
  <section class="empty">
    <h2>还没有分析项目</h2>
    <p>先创建一个明确的授权范围，再导入源码压缩包或 ELF / PE 样本。</p>
    <button class="secondary" on:click={() => showProjectForm = true}>定义第一个项目</button>
  </section>
{:else}
  <section class="panel table-panel" aria-label="项目列表">
    <div class="project-list">
      {#each projects as project (project.id)}
        <button class="project-row" on:click={() => onOpenProject(project)}>
          <span class="project-main"><b>{project.name}</b><small>{project.input_scope.join(" / ")}</small></span>
          <span class={`badge ${project.permission_mode === "request_permission" ? "muted" : "ok"}`}>{project.permission_mode === "request_permission" ? "请求许可" : "完全访问"}</span>
          <span class={`badge ${project.exploit_validation_enabled ? "accent" : "muted"}`}>{project.exploit_validation_enabled ? "利用验证开启" : "利用验证关闭"}</span>
          <time>{formatDate(project.created_at)}</time>
          <span class="arrow" aria-hidden="true">→</span>
        </button>
      {/each}
    </div>
  </section>
{/if}
