<script lang="ts">
  import { onMount } from "svelte";
  import type {
    Artifact,
    ArtifactKind,
    ArtifactVersion,
    Finding,
  Poc,
    Job,
    Project,
    QueueEvent,
    ResourceBudget,
    Task,
    TaskResult,
    TaskStatus,
  } from "@vulnweaver/contracts";
  import { api, ApiError, taskEventSocket, type FindingEvidenceDetail, type ProductSettings, type Session } from "./lib/api";

  type View = "overview" | "project" | "task" | "settings";

  const defaultBudget: ResourceBudget = {
    max_model_tokens: 100000,
    cpu_millis: 2000,
    memory_bytes: 2147483648,
    disk_bytes: 10737418240,
    max_tool_concurrency: 2,
    max_dynamic_runs: 0,
    timeout_seconds: 3600,
  };

  const statusText: Record<TaskStatus, string> = {
    created: "已登记", validating: "校验中", analyzing: "分析中", reviewing: "复核中",
    verifying: "验证中", exploiting: "利用验证", reporting: "报告中", completed: "已完成",
    failed: "已失败", cancelled: "已取消",
  };
  const resultText: Record<TaskResult, string> = {
    success: "已产生候选结果",
    partial: "部分完成：有执行单元未成功",
    no_findings: "扫描已完成，未发现候选问题",
  };

  let session: Session | null = null;
  let registrationOpen = false;
  let booting = true;
  let busy = false;
  let error = "";
  let notice = "";
  let view: View = "overview";
  let projects: Project[] = [];
  let selectedProject: Project | null = null;
  let artifacts: Artifact[] = [];
  let artifactVersions = new Map<string, ArtifactVersion>();
  let tasks: Task[] = [];
  let selectedTask: Task | null = null;
  let jobs: Job[] = [];
  let findings: Finding[] = [];
  let selectedFinding: Finding | null = null;
  let selectedEvidence: FindingEvidenceDetail[] = [];
  let selectedPocs: Poc[] = [];
  let proofScriptRef = "";
  let proofImageDigest = "sha256:";
  let reportVersionIds: string[] = [];
  let events: QueueEvent[] = [];
  let observability: Record<string, unknown> = {};
  let socket: WebSocket | null = null;
  let productSettings: ProductSettings | null = null;
  let reviewApiKey = "";
  let clearReviewApiKey = false;

  let username = "";
  let password = "";
  let currentPassword = "";
  let newPassword = "";
  let confirmPassword = "";
  let registrationPassword = "";
  let registrationConfirmation = "";
  let projectName = "";
  let projectScope = "已授权本地样本";
  let permissionMode: "request_permission" | "full_access" = "request_permission";
  let exploitEnabled = false;
  let showProjectForm = false;
  let uploadKind: ArtifactKind = "source_archive";
  let uploadFile: File | null = null;
  let selectedVersionIds: string[] = [];

  onMount(() => {
    void (async () => {
      try {
        session = await api.me();
        if (!session.must_change_password) await loadProjects();
      } catch (caught) {
        if (caught instanceof ApiError && caught.status === 401) {
          registrationOpen = (await api.installation()).registration_open;
        } else showError(caught);
      } finally {
        booting = false;
      }
    })();
    return () => socket?.close();
  });

  function showError(caught: unknown): void {
    if (caught instanceof ApiError) {
      error = `${caught.message}${caught.correlationId ? ` · 追踪 ${caught.correlationId}` : ""}`;
    } else {
      error = caught instanceof Error ? caught.message : "发生未知错误";
    }
  }

  function displayResult(result: TaskResult | null): string {
    return result ? resultText[result] : "尚未生成";
  }

  function failureContext(job: Job): string {
    if (!job.failure) return "";
    const details = job.failure.details;
    const tool = typeof details.tool_name === "string" ? `工具：${details.tool_name}` : "";
    const reason = typeof details.reason === "string" ? `原因：${details.reason}` : "";
    const exitCode = typeof details.exit_code === "number" ? `退出码：${details.exit_code}` : "";
    return [tool, reason, exitCode].filter(Boolean).join(" · ");
  }

  function begin(): void {
    busy = true;
    error = "";
    notice = "";
  }

  function done(message = ""): void {
    busy = false;
    notice = message;
  }

  async function login(): Promise<void> {
    begin();
    try {
      session = await api.login(username, password);
      password = "";
      if (!session.must_change_password) await loadProjects();
      done();
    } catch (caught) { busy = false; showError(caught); }
  }

  async function register(): Promise<void> {
    if (registrationPassword !== registrationConfirmation) { error = "两次输入的密码不一致"; return; }
    begin();
    try {
      session = await api.register(username, registrationPassword);
      registrationPassword = registrationConfirmation = "";
      registrationOpen = false;
      await loadProjects();
      done("管理员账号已创建");
    } catch (caught) {
      busy = false;
      if (caught instanceof ApiError && caught.status === 409) registrationOpen = false;
      showError(caught);
    }
  }

  async function changePassword(): Promise<void> {
    if (newPassword !== confirmPassword) { error = "两次输入的新密码不一致"; return; }
    begin();
    try {
      await api.changePassword(currentPassword, newPassword);
      session = await api.me();
      currentPassword = newPassword = confirmPassword = "";
      await loadProjects();
      done("密码已更新");
    } catch (caught) { busy = false; showError(caught); }
  }

  async function logout(): Promise<void> {
    begin();
    try { await api.logout(); } catch { /* A stale session is locally cleared either way. */ }
    socket?.close();
    session = null; projects = []; selectedProject = null; selectedTask = null;
    done();
  }

  async function loadProjects(): Promise<void> {
    projects = await api.projects();
  }

  async function openSettings(): Promise<void> {
    begin();
    try { socket?.close(); view = "settings"; productSettings = await api.settings(); done(); }
    catch (caught) { busy = false; showError(caught); }
  }

  async function saveSettings(): Promise<void> {
    if (!productSettings) return;
    begin();
    try {
      const { schema_version: _schema, api_key_configured: _configured, ...values } = productSettings;
      productSettings = await api.updateSettings({
        ...values,
        review_model_api_key: reviewApiKey || null,
        clear_review_model_api_key: clearReviewApiKey,
      });
      reviewApiKey = ""; clearReviewApiKey = false;
      done("设置已保存；模型连接设置会在分析 Worker 下次启动时生效");
    } catch (caught) { busy = false; showError(caught); }
  }

  async function updatePasswordFromSettings(): Promise<void> {
    if (newPassword !== confirmPassword) { error = "两次输入的新密码不一致"; return; }
    begin();
    try {
      await api.changePassword(currentPassword, newPassword);
      currentPassword = newPassword = confirmPassword = "";
      done("密码已更新，其他会话已撤销");
    } catch (caught) { busy = false; showError(caught); }
  }

  async function createProject(): Promise<void> {
    if (!projectName.trim()) { error = "请输入项目名称"; return; }
    begin();
    try {
      const project = await api.createProject({
        name: projectName.trim(), input_scope: [projectScope.trim()], permission_mode: permissionMode,
        exploit_validation_enabled: exploitEnabled, resource_budget: defaultBudget,
      });
      projects = [project, ...projects]; showProjectForm = false; projectName = "";
      await openProject(project); done("项目已创建");
    } catch (caught) { busy = false; showError(caught); }
  }

  async function openProject(project: Project): Promise<void> {
    begin();
    try {
      socket?.close(); selectedProject = project; selectedTask = null; view = "project";
      [artifacts, tasks] = await Promise.all([api.artifacts(project.id), api.tasks(project.id)]);
      const details = await Promise.all(artifacts.map((item) => api.artifact(project.id, item.id)));
      artifactVersions = new Map(details.flatMap((detail) => detail.versions.map((version) => [version.id, version])));
      selectedVersionIds = []; done();
    } catch (caught) { busy = false; showError(caught); }
  }

  async function upload(): Promise<void> {
    if (!selectedProject || !uploadFile) { error = "请选择要导入的样本"; return; }
    begin();
    try {
      const detail = await api.upload(selectedProject.id, uploadKind, uploadFile);
      artifacts = [detail.artifact, ...artifacts];
      for (const version of detail.versions) artifactVersions.set(version.id, version);
      artifactVersions = new Map(artifactVersions); uploadFile = null;
      const input = document.querySelector<HTMLInputElement>("#sample-file"); if (input) input.value = "";
      done("样本已登记到内容寻址工件库");
    } catch (caught) { busy = false; showError(caught); }
  }

  function toggleVersion(versionId: string): void {
    selectedVersionIds = selectedVersionIds.includes(versionId)
      ? selectedVersionIds.filter((id) => id !== versionId) : [...selectedVersionIds, versionId];
  }

  async function createTask(): Promise<void> {
    if (!selectedProject || selectedVersionIds.length === 0) { error = "请至少选择一个样本"; return; }
    begin();
    try {
      const task = await api.createTask(selectedProject.id, {
        artifact_version_ids: selectedVersionIds, resource_budget: defaultBudget,
      });
      tasks = [task, ...tasks.filter((item) => item.id !== task.id)];
      await openTask(task); done("分析任务已投递");
    } catch (caught) { busy = false; showError(caught); }
  }

  async function openTask(task: Task): Promise<void> {
    begin();
    try {
      socket?.close(); selectedTask = await api.task(task.id); view = "task";
      selectedFinding = null; selectedEvidence = []; selectedPocs = [];
      [jobs, events, findings, observability] = await Promise.all([api.jobs(task.id), api.events(task.id), api.findings(task.id), api.observability(task.id)]);
      await refreshReportResults();
      connectEvents(task.id); done();
    } catch (caught) { busy = false; showError(caught); }
  }

  function connectEvents(taskId: string): void {
    const after = events.reduce((max, event) => Math.max(max, event.sequence), -1);
    socket = taskEventSocket(taskId, after);
    socket.onmessage = async (message) => {
      const event = JSON.parse(message.data as string) as QueueEvent;
      if (!events.some((item) => item.event_id === event.event_id)) events = [...events, event];
      if (event.event_type === "task.status_changed" && selectedTask) {
        selectedTask = { ...selectedTask, status: event.payload.status, result: event.payload.result };
      }
      [jobs, findings, observability] = await Promise.all([api.jobs(taskId), api.findings(taskId), api.observability(taskId)]);
      await refreshReportResults();
    };
  }

  async function refreshReportResults(): Promise<void> {
    const results = await Promise.all(jobs
      .filter((job) => job.kind === "report")
      .map((job) => api.jobResult(job.id)));
    reportVersionIds = results.flatMap((result) =>
      "produced_artifact_version_ids" in result ? result.produced_artifact_version_ids : []);
    const versions = await Promise.all(reportVersionIds.map((id) => api.artifactVersion(id)));
    for (const version of versions) artifactVersions.set(version.id, version);
    artifactVersions = new Map(artifactVersions);
  }

  async function createProof(kind: "proof_of_concept" | "exploit"): Promise<void> {
    if (!selectedFinding) return;
    if (!proofScriptRef || !proofImageDigest || proofImageDigest === "sha256:") {
      error = "请填写脚本引用和固定镜像摘要"; return;
    }
    begin();
    try {
      const job = await api.createProof(selectedFinding.id, {
        script_ref: proofScriptRef, image_digest: proofImageDigest,
        permission_mode: selectedProject?.permission_mode ?? "request_permission",
        resource_budget: selectedTask?.resource_budget ?? defaultBudget, kind,
      });
      jobs = [job, ...jobs.filter((item) => item.id !== job.id)];
      done(`${kind === "exploit" ? "Exploit" : "Proof"} Job 已投递`);
    } catch (caught) { busy = false; showError(caught); }
  }

  async function selectFinding(finding: Finding): Promise<void> {
    selectedFinding = finding;
    try {
      [selectedEvidence, selectedPocs] = await Promise.all([
        api.findingEvidence(finding.id),
        api.findingPocs(finding.id),
      ]);
    } catch (caught) { showError(caught); }
  }

  async function cancelTask(): Promise<void> {
    if (!selectedTask) return;
    begin();
    try { selectedTask = await api.cancelTask(selectedTask.id); done("任务已取消"); }
    catch (caught) { busy = false; showError(caught); }
  }

  async function createReport(format: "markdown" | "pdf" | "sarif"): Promise<void> {
    if (!selectedTask || selectedTask.artifact_version_ids.length === 0) return;
    const versionId = selectedTask.artifact_version_ids[0];
    const version = artifactVersions.get(versionId);
    if (!version) { error = "当前样本版本信息尚未加载"; return; }
    begin();
    try {
      const job = await api.createReport(selectedTask.id, {
        artifact_id: version.artifact_id,
        version_id: version.id,
        parent_version_id: version.parent_version_id,
        format,
      });
      jobs = [job, ...jobs.filter((item) => item.id !== job.id)];
      done(`${format.toUpperCase()} 报告任务已投递`);
    } catch (caught) { busy = false; showError(caught); }
  }

  function goOverview(): void {
    socket?.close(); view = "overview"; selectedProject = null; selectedTask = null;
  }

  function shortId(id: string): string { return id.includes(":") ? id.split(":")[1].slice(0, 8) : id.slice(0, 8); }
  function formatDate(value: string): string { return new Intl.DateTimeFormat("zh-CN", { dateStyle: "medium", timeStyle: "short" }).format(new Date(value)); }
  function fileName(versionId: string): string { return String(artifactVersions.get(versionId)?.generation_config.filename ?? "未命名样本"); }
</script>

<svelte:head><title>{selectedProject ? `${selectedProject.name} · VulnWeaver` : "VulnWeaver · 漏洞织鉴"}</title></svelte:head>

{#if booting}
  <main class="boot" aria-busy="true"><div class="brand-mark">VW</div><p>正在恢复工作台…</p></main>
{:else if !session}
  <main class="auth-shell">
    <section class="auth-intro">
      <a class="wordmark" href="/" aria-label="VulnWeaver 首页"><span>VW</span> VULNWEAVER</a>
      <div class="auth-copy"><p class="eyebrow">EVIDENCE-DRIVEN SECURITY</p><h1>让每一个漏洞结论<br />都能被追溯。</h1><p>为已授权样本编排静态分析、独立复核与受控验证。模型提出观点，证据决定结论。</p></div>
      <div class="trust-line"><span>● 默认禁网</span><span>● 原始工件不可变</span><span>● 控制面 / 执行面隔离</span></div>
    </section>
    <section class="auth-panel">
      <form class="auth-form" on:submit|preventDefault={registrationOpen ? register : login}>
        <p class="step">01 / 个人工作台</p><h2>{registrationOpen ? "创建管理员账号" : "登录"}</h2><p class="muted">{registrationOpen ? "这是全新安装。创建唯一的本地管理员后即可开始使用。" : "使用你的本地管理员账号继续。"}</p>
        {#if error}<div class="alert error" role="alert">{error}</div>{/if}
        <label>账号<input bind:value={username} autocomplete="username" required /></label>
        {#if registrationOpen}
          <label>密码<input bind:value={registrationPassword} type="password" minlength="12" autocomplete="new-password" required /></label>
          <label>确认密码<input bind:value={registrationConfirmation} type="password" minlength="12" autocomplete="new-password" required /></label>
        {:else}<label>密码<input bind:value={password} type="password" autocomplete="current-password" required /></label>{/if}
        <button class="primary wide" disabled={busy}>{busy ? "正在处理…" : registrationOpen ? "创建账号并进入" : "进入工作台"}</button>
        <p class="fine-print">仅用于明确授权的本地样本与开源项目。</p>
      </form>
    </section>
  </main>
{:else if session.must_change_password}
  <main class="auth-shell password-shell">
    <section class="auth-intro"><a class="wordmark" href="/" aria-label="VulnWeaver"><span>VW</span> VULNWEAVER</a><div class="auth-copy"><p class="eyebrow">FIRST ACCESS</p><h1>在继续之前，<br />请设置你的密码。</h1></div></section>
    <section class="auth-panel"><form class="auth-form" on:submit|preventDefault={changePassword}>
      <p class="step">02 / 初始安全设置</p><h2>更改密码</h2><p class="muted">新密码至少 12 个字符，更新后当前会话保留。</p>
      {#if error}<div class="alert error" role="alert">{error}</div>{/if}
      <label>初始密码<input bind:value={currentPassword} type="password" autocomplete="current-password" required /></label>
      <label>新密码<input bind:value={newPassword} type="password" minlength="12" autocomplete="new-password" required /></label>
      <label>确认新密码<input bind:value={confirmPassword} type="password" minlength="12" autocomplete="new-password" required /></label>
      <button class="primary wide" disabled={busy}>{busy ? "正在更新…" : "保存并继续"}</button>
    </form></section>
  </main>
{:else}
  <div class="workspace">
    <header class="topbar"><button class="wordmark button-reset" on:click={goOverview}><span>VW</span> VULNWEAVER</button><div class="top-actions"><span class="system-state"><i></i> CONTROL PLANE</span><span class="account">{session.username}</span><button class="text-button" on:click={logout}>退出</button></div></header>
    <aside class="sidebar">
      <nav aria-label="主导航"><button class:active={view === "overview"} on:click={goOverview}><b>01</b> 项目</button>{#if selectedProject}<button class:active={view === "project"} on:click={() => openProject(selectedProject!)}><b>02</b> 样本与任务</button>{/if}{#if selectedTask}<button class:active={view === "task"} on:click={() => openTask(selectedTask!)}><b>03</b> 执行轨迹</button>{/if}<button class:active={view === "settings"} on:click={() => void openSettings()}><b>04</b> 设置</button></nav>
      <div class="sidebar-note"><span>SECURITY BOUNDARY</span><p>动态执行只允许经策略校验后进入一次性沙箱。</p></div>
    </aside>
    <main class="content">
      {#if error}<div class="alert error global" role="alert"><span>{error}</span><button on:click={() => error = ""}>关闭</button></div>{/if}
      {#if notice}<div class="alert success global" role="status"><span>{notice}</span><button on:click={() => notice = ""}>关闭</button></div>{/if}

      {#if view === "settings" && productSettings}
        <section class="page-heading"><div><p class="eyebrow">INSTALLATION SETTINGS</p><h1>产品设置</h1><p>这些设置存储在 PostgreSQL。数据库、Cookie 安全策略、内部服务地址和 API 密钥仍由部署方安全注入。</p></div></section>
        <form class="settings-form section-block" on:submit|preventDefault={saveSettings}>
          <div class="section-head"><div><span>REVIEW MODEL</span><h2>独立复核模型</h2></div><small>{productSettings.api_key_configured ? "API Key 已配置（不回显）" : "API Key 未配置"}</small></div>
          <label>OpenAI 兼容端点<input bind:value={productSettings.review_model_base_url} placeholder="https://example.com/v1" /></label>
          <label>模型名称<input bind:value={productSettings.review_model_name} placeholder="review-model" /></label>
          <label>API Key<input bind:value={reviewApiKey} type="password" autocomplete="new-password" placeholder={productSettings.api_key_configured ? "留空以保留现有值" : "输入 API Key"} /></label>
          {#if productSettings.api_key_configured}<label class="check"><input type="checkbox" bind:checked={clearReviewApiKey} /><span><b>清除已保存的 API Key</b><small>保存后立即删除；输入新值会在未勾选时替换旧值。</small></span></label>{/if}
          <div class="settings-grid"><label>超时（秒）<input bind:value={productSettings.review_model_timeout_seconds} type="number" min="1" max="600" /></label><label>最大尝试次数<input bind:value={productSettings.review_model_max_attempts} type="number" min="1" max="10" /></label><label>结构修复次数<input bind:value={productSettings.review_model_repair_attempts} type="number" min="0" max="5" /></label><label>请求最小间隔（秒）<input bind:value={productSettings.review_model_min_interval_seconds} type="number" min="0" max="3600" step="0.1" /></label></div>
          <button class="primary" disabled={busy}>保存设置</button>
        </form>
        <form class="settings-form section-block full" on:submit|preventDefault={updatePasswordFromSettings}>
          <div class="section-head"><div><span>ACCOUNT SECURITY</span><h2>更改密码</h2></div><small>成功后保留当前会话并撤销其他会话</small></div>
          <label>当前密码<input bind:value={currentPassword} type="password" autocomplete="current-password" required /></label>
          <div class="settings-grid"><label>新密码<input bind:value={newPassword} type="password" minlength="12" autocomplete="new-password" required /></label><label>确认新密码<input bind:value={confirmPassword} type="password" minlength="12" autocomplete="new-password" required /></label></div>
          <button class="primary" disabled={busy}>更新密码</button>
        </form>
      {:else if view === "overview"}
        <section class="page-heading"><div><p class="eyebrow">AUTHORIZED WORKSPACE</p><h1>项目与分析范围</h1><p>每个项目隔离样本、任务和证据链，运行前明确授权边界。</p></div><button class="primary" on:click={() => showProjectForm = !showProjectForm}>{showProjectForm ? "收起" : "+ 新建项目"}</button></section>
        <section class="metric-strip"><div><strong>{projects.length}</strong><span>已授权项目</span></div><div><strong>{projects.filter((p) => p.exploit_validation_enabled).length}</strong><span>开启利用验证</span></div><div><strong>{projects.filter((p) => p.permission_mode === "request_permission").length}</strong><span>需运行许可</span></div></section>
        {#if showProjectForm}<form class="inline-form" on:submit|preventDefault={createProject}><div class="form-title"><span>NEW SCOPE</span><h2>创建项目</h2></div><label>项目名称<input bind:value={projectName} placeholder="例：网关 2.4 安全复核" required /></label><label>授权范围<input bind:value={projectScope} required /></label><label>运行模式<select bind:value={permissionMode}><option value="request_permission">每次动态执行前请求许可</option><option value="full_access">在已授权范围内自动执行</option></select></label><label class="check"><input type="checkbox" bind:checked={exploitEnabled} /><span><b>允许利用验证</b><small>仅对 confirmed Finding，且仍需经策略门禁。</small></span></label><button class="primary" disabled={busy}>创建并进入</button></form>{/if}
        {#if projects.length === 0}<section class="empty"><span class="empty-index">00</span><h2>还没有分析项目</h2><p>先创建一个明确的授权范围，再导入源码压缩包或 ELF / PE 样本。</p><button class="secondary" on:click={() => showProjectForm = true}>定义第一个项目</button></section>{:else}<section class="project-list" aria-label="项目列表">{#each projects as project, index}<button class="project-row" on:click={() => openProject(project)}><span class="row-index">{String(index + 1).padStart(2, "0")}</span><span class="project-main"><b>{project.name}</b><small>{project.input_scope.join(" · ")}</small></span><span class="mode">{project.permission_mode === "request_permission" ? "请求许可" : "完全访问"}</span><span class:enabled={project.exploit_validation_enabled} class="exploit">{project.exploit_validation_enabled ? "EXPLOIT ON" : "EXPLOIT OFF"}</span><time>{formatDate(project.created_at)}</time><span class="arrow">→</span></button>{/each}</section>{/if}
      {:else if view === "project" && selectedProject}
        <section class="page-heading"><div><button class="breadcrumb" on:click={goOverview}>项目 /</button><p class="eyebrow">{shortId(selectedProject.id)}</p><h1>{selectedProject.name}</h1><p>{selectedProject.input_scope.join(" · ")}</p></div><span class="scope-badge">{selectedProject.permission_mode === "request_permission" ? "动态执行需许可" : "授权范围内自动执行"}</span></section>
        <section class="split-grid"><div class="section-block"><div class="section-head"><div><span>INPUT / 01</span><h2>导入样本</h2></div><small>原始工件不可变</small></div><div class="upload-box"><label>样本类型<select bind:value={uploadKind}><option value="source_archive">源码压缩包</option><option value="elf">ELF 二进制</option><option value="pe">PE 二进制</option></select></label><label class="file-picker" for="sample-file"><span>{uploadFile?.name ?? "选择本地样本"}</span><small>{uploadFile ? `${(uploadFile.size / 1048576).toFixed(2)} MB` : "ZIP / TAR / ELF / PE"}</small></label><input id="sample-file" class="visually-hidden" type="file" on:change={(e) => uploadFile = e.currentTarget.files?.[0] ?? null} /><button class="primary" on:click={upload} disabled={busy || !uploadFile}>导入工件库</button></div></div>
          <div class="section-block"><div class="section-head"><div><span>ANALYSIS / 02</span><h2>创建任务</h2></div><small>选择一个或多个样本版本</small></div>{#if artifacts.length === 0}<div class="compact-empty">导入样本后，可在此创建分析任务。</div>{:else}<div class="sample-options">{#each artifacts as artifact}<label class:selected={selectedVersionIds.includes(artifact.current_version_id)} class="sample-option"><input type="checkbox" checked={selectedVersionIds.includes(artifact.current_version_id)} on:change={() => toggleVersion(artifact.current_version_id)} /><span><b>{fileName(artifact.current_version_id)}</b><small>{artifact.kind.toUpperCase()} · sha256:{artifactVersions.get(artifact.current_version_id)?.digest.slice(0, 12)}…</small></span></label>{/each}</div><button class="primary" on:click={createTask} disabled={busy || selectedVersionIds.length === 0}>投递分析任务 <span>{selectedVersionIds.length || ""}</span></button>{/if}</div></section>
        <section class="section-block full"><div class="section-head"><div><span>RUNS / 03</span><h2>最近任务</h2></div><small>{tasks.length} 条记录</small></div>{#if tasks.length === 0}<div class="compact-empty">暂无执行记录。</div>{:else}<div class="task-list">{#each tasks as task}<button on:click={() => openTask(task)}><span class={`status-dot ${task.status}`}></span><span><b>{statusText[task.status]}</b><small>{shortId(task.id)} · {task.artifact_version_ids.length} 个输入</small></span><time>{formatDate(task.updated_at)}</time><span>→</span></button>{/each}</div>{/if}</section>
      {:else if view === "task" && selectedTask}
        <section class="page-heading task-heading"><div><button class="breadcrumb" on:click={() => openProject(selectedProject!)}>{selectedProject?.name} /</button><p class="eyebrow">TASK {shortId(selectedTask.id)}</p><h1>{statusText[selectedTask.status]}</h1><p>结果：{displayResult(selectedTask.result)} · 更新于 {formatDate(selectedTask.updated_at)}</p></div><div class="task-actions"><span class={`large-status ${selectedTask.status}`}>{selectedTask.status.toUpperCase()}</span>{#if !["completed", "failed", "cancelled"].includes(selectedTask.status)}<button class="danger" on:click={cancelTask} disabled={busy}>取消任务</button>{/if}</div></section>
        <section class="metric-strip task-metrics"><div><strong>{JSON.stringify(observability.jobs_by_status ?? {})}</strong><span>状态汇总</span></div><div><strong>{jobs.length}</strong><span>Jobs</span></div><div><strong>{events.length}</strong><span>事件</span></div><div><strong>{findings.length}</strong><span>候选问题</span></div><div><strong>{selectedTask.resource_budget.max_dynamic_runs}</strong><span>动态运行额度</span></div></section>
        <section class="section-block full"><div class="section-head"><div><span>FINDINGS / REPORTS</span><h2>问题与报告</h2></div><div class="task-actions"><button class="secondary" on:click={() => createReport("markdown")} disabled={busy}>生成 Markdown</button><button class="secondary" on:click={() => createReport("sarif")} disabled={busy}>生成 SARIF</button><button class="secondary" on:click={() => createReport("pdf")} disabled={busy}>生成 PDF</button></div></div>{#if findings.length === 0}<div class="compact-empty">当前任务尚未产生候选问题。</div>{:else}<div class="finding-list">{#each findings as finding}<button class="finding-row" on:click={() => void selectFinding(finding)}><span class={`status-dot ${finding.status}`}></span><div><b>{finding.title}</b><small>{finding.severity.toUpperCase()} · {finding.category} · {finding.cwe_id}</small></div><span>{Math.round(finding.confidence * 100)}%</span></button>{/each}</div>{/if}{#if selectedFinding}<article class="finding-detail"><b>{selectedFinding.title}</b><p>{selectedFinding.fix_suggestion}</p><small>位置：{JSON.stringify(selectedFinding.location)} · 证据：{selectedFinding.evidence_ids.length} 条 · POC：{selectedFinding.poc_ids.length} 个</small><div class="proof-actions"><label>脚本引用<input bind:value={proofScriptRef} placeholder="CAS/object reference" /></label><label>镜像摘要<input bind:value={proofImageDigest} placeholder="sha256:..." /></label><button class="secondary" on:click={() => void createProof("proof_of_concept")} disabled={busy}>发起 Proof</button>{#if selectedFinding.status === "confirmed" && selectedProject?.exploit_validation_enabled}<button class="danger" on:click={() => void createProof("exploit")} disabled={busy}>发起 Exploit</button>{/if}</div>{#if selectedEvidence.length > 0}<div class="detail-evidence"><b>证据链</b>{#each selectedEvidence as item}<small>{item.evidence.type} · {item.evidence.strength} · {item.evidence.tool?.name ?? "人工"} · {item.evidence.digest.slice(0, 16)}…</small>{/each}</div>{/if}{#if selectedPocs.length > 0}<div class="detail-evidence"><b>复现记录</b>{#each selectedPocs as poc}<small>{poc.kind} · {poc.status} · {poc.result?.toUpperCase() ?? "未执行"}</small>{/each}</div>{/if}</article>{/if}{#if reportVersionIds.length > 0}<div class="report-links">{#each reportVersionIds as versionId}{#if artifactVersions.get(versionId)}<a class="secondary" href={api.artifactContentUrl(artifactVersions.get(versionId)!.artifact_id, versionId)} download>下载报告 · {artifactVersions.get(versionId)!.generation_config.format ?? "文件"}</a>{/if}{/each}</div>{/if}</section>
        <section class="task-grid"><div class="section-block"><div class="section-head"><div><span>JOBS</span><h2>执行单元</h2></div><small>由编排层创建</small></div>{#if jobs.length === 0}<div class="compact-empty">等待编排服务消费 <code>task.requested</code>。</div>{:else}<div class="job-list">{#each jobs as job}<article><span class={`status-dot ${job.status}`}></span><div><b>{job.kind.replaceAll("_", " ")}</b><small>{job.status} · attempt {job.attempt}/{job.retry_policy.max_attempts}</small></div>{#if job.failure}<p>{job.failure.message}</p><small>{job.failure.code}{failureContext(job) ? ` · ${failureContext(job)}` : ""}</small>{/if}</article>{/each}</div>{/if}</div>
          <div class="section-block"><div class="section-head"><div><span>EVENT STREAM</span><h2>决策与状态轨迹</h2></div><small class="live"><i></i> LIVE</small></div>{#if events.length === 0}<div class="compact-empty">尚未接收事件。</div>{:else}<ol class="timeline">{#each [...events].reverse() as event}<li><span>{String(event.sequence).padStart(2, "0")}</span><div><b>{event.event_type}</b><small>{formatDate(event.occurred_at)} · {shortId(event.event_id)}</small><details><summary>载荷</summary><code>{JSON.stringify(event.payload)}</code></details></div></li>{/each}</ol>{/if}</div></section>
      {/if}
    </main>
  </div>
{/if}
