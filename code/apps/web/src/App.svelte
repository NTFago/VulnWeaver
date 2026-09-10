<script lang="ts">
  import { onMount } from "svelte";
  import type {
    AgentRun,
    Artifact,
    ArtifactKind,
    ArtifactVersion,
    Finding,
    Job,
    PairFunction,
    Project,
    QueueEvent,
    Poc,
    Review,
    Task,
  } from "@vulnweaver/contracts";
  import { api, ApiError, taskEventSocket, type FindingEvidenceDetail, type ProductSettings, type Session } from "./lib/api";
  import AuthView from "./lib/views/AuthView.svelte";
  import SettingsView, { type SettingsSavePayload } from "./lib/views/SettingsView.svelte";
  import ProjectsView, { type NewProjectPayload } from "./lib/views/ProjectsView.svelte";
  import ProjectView from "./lib/views/ProjectView.svelte";
  import TaskView from "./lib/views/TaskView.svelte";

  type View = "settings" | "overview" | "project" | "task";

  let session: Session | null = null;
  let registrationOpen = false;
  let booting = true;
  let busy = false;
  let error = "";
  let notice = "";
  let view: View = "settings";
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
  let selectedReviews: Review[] = [];
  let events: QueueEvent[] = [];
  let observability: Record<string, unknown> = {};
  let socket: WebSocket | null = null;
  let socketGeneration = 0;
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  let productSettings: ProductSettings | null = null;
  let pairNeighborhood: Record<string, unknown> | null = null;
  let pairFunctions: PairFunction[] = [];
  let agentRuns: AgentRun[] = [];
  let selectedFunctionId: string | null = null;
  let reportVersionIds: string[] = [];

  onMount(() => {
    void (async () => {
      try {
        session = await api.me();
        if (!session.must_change_password) {
          await loadProjects();
          await openSettings();
        }
      } catch (caught) {
        if (caught instanceof ApiError && caught.status === 401) {
          registrationOpen = (await api.installation()).registration_open;
        } else showError(caught);
      } finally {
        booting = false;
      }
    })();
    return disconnectEvents;
  });

  function showError(caught: unknown): void {
    if (caught instanceof ApiError) {
      error = `${caught.message}${caught.correlationId ? ` · 追踪 ${caught.correlationId}` : ""}`;
    } else {
      error = caught instanceof Error ? caught.message : "发生未知错误";
    }
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

  async function login(username: string, password: string): Promise<void> {
    begin();
    try {
      session = await api.login(username, password);
      if (!session.must_change_password) {
        await loadProjects();
        await openSettings();
      }
      done();
    } catch (caught) { busy = false; showError(caught); }
  }

  async function register(username: string, password: string): Promise<void> {
    begin();
    try {
      session = await api.register(username, password);
      registrationOpen = false;
      await loadProjects();
      await openSettings();
      done("管理员账号已创建");
    } catch (caught) {
      busy = false;
      if (caught instanceof ApiError && caught.status === 409) registrationOpen = false;
      showError(caught);
    }
  }

  async function changePasswordFromGate(currentPassword: string, newPassword: string): Promise<void> {
    begin();
    try {
      await api.changePassword(currentPassword, newPassword);
      session = await api.me();
      await loadProjects();
      await openSettings();
      done("密码已更新");
    } catch (caught) { busy = false; showError(caught); }
  }

  async function logout(): Promise<void> {
    begin();
    try { await api.logout(); } catch { /* A stale session is locally cleared either way. */ }
    disconnectEvents();
    session = null; projects = []; selectedProject = null; selectedTask = null;
    done();
  }

  async function loadProjects(): Promise<void> {
    projects = await api.projects();
  }

  type TierName = "planning" | "audit" | "review" | "report";
  const tierNames: TierName[] = ["planning", "audit", "review", "report"];

  function emptyTierConfig() {
    return {
      protocol: "openai" as const,
      base_url: "",
      model_name: "",
      context_window_tokens: 0,
      thinking_mode: "off" as const,
      thinking_budget_tokens: 0,
      timeout_seconds: 0,
      max_attempts: 0,
    };
  }

  function withDeploymentDefaults(raw: ProductSettings): ProductSettings {
    // Older installations may not have the deployment fields persisted yet.
    const tiers = { ...raw.model_tiers };
    for (const tier of tierNames) {
      tiers[tier] = { ...emptyTierConfig(), ...(tiers[tier] ?? {}) };
    }
    return {
      ...raw,
      model_tiers: tiers,
      tier_api_keys_configured: raw.tier_api_keys_configured ?? {},
      tool_image_digests: raw.tool_image_digests ?? { binary_tools: null, proof_tool: null, afl_casr: null },
      sandbox_budgets: raw.sandbox_budgets ?? {
        afl: { cpu_millis: 0, memory_bytes: 0, disk_bytes: 0, timeout_seconds: 0 },
        proof: { cpu_millis: 0, memory_bytes: 0, disk_bytes: 0, timeout_seconds: 0 },
        binary: { cpu_millis: 0, memory_bytes: 0, disk_bytes: 0, timeout_seconds: 0 },
      },
      fuzz_budgets: raw.fuzz_budgets ?? { max_executions: 0, max_duration_seconds: 0, max_crashes: 0 },
      sandbox_runner_timeout_seconds: raw.sandbox_runner_timeout_seconds ?? 0,
      fuzz_runner_timeout_seconds: raw.fuzz_runner_timeout_seconds ?? 0,
      angr_enabled: raw.angr_enabled ?? null,
    };
  }

  async function openSettings(): Promise<void> {
    begin();
    try {
      disconnectEvents(); view = "settings";
      productSettings = withDeploymentDefaults(await api.settings());
      done();
    }
    catch (caught) { busy = false; showError(caught); }
  }

  async function saveSettings(payload: SettingsSavePayload): Promise<boolean> {
    if (!productSettings) return false;
    begin();
    try {
      const { schema_version: _schema, api_key_configured: _configured, tier_api_keys_configured: _tierKeys, ...values } = payload.settings;
      productSettings = withDeploymentDefaults(await api.updateSettings({
        ...values,
        review_model_api_key: payload.reviewApiKey || null,
        clear_review_model_api_key: payload.clearReviewApiKey,
        tier_api_keys: payload.tierApiKeys,
        clear_tier_api_keys: payload.clearTierApiKeys,
      }));
      done("设置已保存；模型与执行配置由 Worker 在下一次任务时自动生效");
      return true;
    } catch (caught) { busy = false; showError(caught); return false; }
  }

  async function updatePasswordFromSettings(currentPassword: string, newPassword: string): Promise<boolean> {
    begin();
    try {
      await api.changePassword(currentPassword, newPassword);
      done("密码已更新，其他会话已撤销");
      return true;
    } catch (caught) { busy = false; showError(caught); return false; }
  }

  async function createProject(payload: NewProjectPayload): Promise<boolean> {
    begin();
    try {
      const project = await api.createProject({
        name: payload.name,
        input_scope: payload.input_scope,
        permission_mode: payload.permission_mode,
        exploit_validation_enabled: payload.exploit_validation_enabled,
        resource_budget: payload.resource_budget,
      });
      projects = [project, ...projects];
      await openProject(project); done("项目已创建");
      return true;
    } catch (caught) { busy = false; showError(caught); return false; }
  }

  async function openProject(project: Project): Promise<void> {
    begin();
    try {
      disconnectEvents(); selectedProject = project; selectedTask = null; view = "project";
      [artifacts, tasks] = await Promise.all([api.artifacts(project.id), api.tasks(project.id)]);
      const details = await Promise.all(artifacts.map((item) => api.artifact(project.id, item.id)));
      artifactVersions = new Map(details.flatMap((detail) => detail.versions.map((version) => [version.id, version])));
      done();
    } catch (caught) { busy = false; showError(caught); }
  }

  async function upload(kind: ArtifactKind, file: File): Promise<boolean> {
    if (!selectedProject) return false;
    begin();
    try {
      const detail = await api.upload(selectedProject.id, kind, file);
      artifacts = [detail.artifact, ...artifacts];
      for (const version of detail.versions) artifactVersions.set(version.id, version);
      artifactVersions = new Map(artifactVersions);
      done("样本已登记到内容寻址工件库");
      return true;
    } catch (caught) { busy = false; showError(caught); return false; }
  }

  async function createTask(versionIds: string[]): Promise<boolean> {
    if (!selectedProject) return false;
    begin();
    try {
      const task = await api.createTask(selectedProject.id, {
        artifact_version_ids: versionIds, resource_budget: selectedProject.resource_budget,
      });
      tasks = [task, ...tasks.filter((item) => item.id !== task.id)];
      await openTask(task); done("分析任务已投递");
      return true;
    } catch (caught) { busy = false; showError(caught); return false; }
  }

  async function openTask(task: Task): Promise<void> {
    begin();
    try {
      disconnectEvents(); selectedTask = await api.task(task.id); view = "task";
      selectedFinding = null; selectedEvidence = []; selectedPocs = []; selectedReviews = [];
      [jobs, events, findings, observability, pairFunctions, agentRuns] = await Promise.all([api.jobs(task.id), api.events(task.id), api.findings(task.id), api.observability(task.id), api.pair(task.id), api.agentRuns(task.id)]);
      await refreshReportResults();
      connectEvents(task.id); done();
    } catch (caught) { busy = false; showError(caught); }
  }

  function disconnectEvents(): void {
    socketGeneration += 1;
    if (reconnectTimer !== null) clearTimeout(reconnectTimer);
    reconnectTimer = null;
    socket?.close();
    socket = null;
  }

  function connectEvents(taskId: string, attempt = 0, generation = socketGeneration): void {
    const after = events.reduce((max, event) => Math.max(max, event.sequence), -1);
    const current = taskEventSocket(taskId, after);
    socket = current;
    current.onmessage = async (message) => {
      const event = JSON.parse(message.data as string) as QueueEvent;
      if (!events.some((item) => item.event_id === event.event_id)) events = [...events, event];
      if (event.event_type === "task.status_changed" && selectedTask) {
        selectedTask = {
          ...selectedTask, status: event.payload.status,
          result: event.payload.result, failure: event.payload.failure,
        };
      }
      [jobs, findings, observability] = await Promise.all([api.jobs(taskId), api.findings(taskId), api.observability(taskId)]);
      await refreshReportResults();
    };
    current.onclose = () => {
      if (generation !== socketGeneration || selectedTask?.id !== taskId || view !== "task") return;
      reconnectTimer = setTimeout(() => void recoverEvents(taskId, attempt + 1, generation), Math.min(1000 * 2 ** attempt, 15000));
    };
  }

  async function recoverEvents(taskId: string, attempt: number, generation: number): Promise<void> {
    if (generation !== socketGeneration || selectedTask?.id !== taskId || view !== "task") return;
    try {
      const after = events.reduce((max, event) => Math.max(max, event.sequence), -1);
      const recovered = await api.events(taskId, after);
      const known = new Set(events.map((event) => event.event_id));
      events = [...events, ...recovered.filter((event) => !known.has(event.event_id))];
      [jobs, findings, observability] = await Promise.all([api.jobs(taskId), api.findings(taskId), api.observability(taskId)]);
      await refreshReportResults();
      connectEvents(taskId, 0, generation);
    } catch {
      reconnectTimer = setTimeout(() => void recoverEvents(taskId, attempt + 1, generation), Math.min(1000 * 2 ** attempt, 15000));
    }
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

  async function createProof(kind: "proof_of_concept" | "exploit", scriptRef: string, imageDigest: string): Promise<void> {
    if (!selectedFinding) return;
    if (!scriptRef || !imageDigest || imageDigest === "sha256:") {
      error = "请填写脚本引用和固定镜像摘要"; return;
    }
    const budget = selectedTask?.resource_budget ?? selectedProject?.resource_budget;
    if (!budget) { error = "请先选择任务"; return; }
    begin();
    try {
      const job = await api.createProof(selectedFinding.id, {
        script_ref: scriptRef, image_digest: imageDigest,
        permission_mode: selectedProject?.permission_mode ?? "request_permission",
        resource_budget: budget, kind,
      });
      jobs = [job, ...jobs.filter((item) => item.id !== job.id)];
      done(`${kind === "exploit" ? "Exploit" : "Proof"} Job 已投递`);
    } catch (caught) { busy = false; showError(caught); }
  }

  async function selectFinding(finding: Finding): Promise<void> {
    selectedFinding = finding;
    try {
      [selectedEvidence, selectedPocs, selectedReviews] = await Promise.all([
        api.findingEvidence(finding.id),
        api.findingPocs(finding.id),
        api.findingReviews(finding.id),
      ]);
    } catch (caught) { showError(caught); }
  }

  async function submitAnnotation(note: string): Promise<boolean> {
    if (!selectedTask || !selectedFinding) return false;
    begin();
    try {
      await api.createAnnotation(selectedTask.id, { target_kind: "finding", target_id: selectedFinding.id, labels: ["人工复核"], note });
      done("标注已保存");
      return true;
    } catch (caught) { busy = false; showError(caught); return false; }
  }

  async function submitReview(outcome: string, rationale: string): Promise<boolean> {
    if (!selectedFinding) return false;
    begin();
    try {
      await api.reviewFinding(selectedFinding.id, outcome, rationale);
      findings = await api.findings(selectedFinding.task_id);
      selectedFinding = findings.find((item) => item.id === selectedFinding?.id) ?? selectedFinding;
      selectedReviews = await api.findingReviews(selectedFinding.id);
      done("复核意见与结论已保存");
      return true;
    } catch (caught) { busy = false; showError(caught); return false; }
  }

  async function selectFunction(fn: PairFunction): Promise<void> {
    selectedFunctionId = fn.id;
    if (!selectedTask) return;
    try { pairNeighborhood = await api.pairNeighborhood(selectedTask.id, fn.id); }
    catch (caught) { showError(caught); }
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
    disconnectEvents(); view = "overview"; selectedProject = null; selectedTask = null;
  }

  function goHome(): void {
    void openSettings();
  }

  /**
   * 任务输入类型：优先取输入工件的 ArtifactKind，
   * 无法解析时按任务已有作业的 JobKind 推断，默认按源码任务处理。
   */
  function deriveTaskType(): "source" | "binary" {
    if (selectedTask) {
      const versionId = selectedTask.artifact_version_ids[0];
      const version = versionId ? artifactVersions.get(versionId) : undefined;
      const artifact = version ? artifacts.find((item) => item.id === version.artifact_id) : undefined;
      if (artifact) {
        if (artifact.kind === "elf" || artifact.kind === "pe") return "binary";
        if (artifact.kind === "source_archive" || artifact.kind === "source_repository") return "source";
      }
    }
    if (jobs.some((job) => job.kind === "binary_analysis")) return "binary";
    return "source";
  }

  $: taskType = deriveTaskType();

  async function retryJobs(jobIds: string[]): Promise<boolean> {
    if (!selectedTask || jobIds.length === 0) return false;
    begin();
    try {
      const results = await Promise.allSettled(jobIds.map((id) => api.retryJob(id)));
      const accepted = results.filter((result) => result.status === "fulfilled").length;
      const firstRejection = results.find((result): result is PromiseRejectedResult => result.status === "rejected");
      if (accepted === 0 && firstRejection) {
        busy = false;
        showError(firstRejection.reason);
        return false;
      }
      jobs = await api.jobs(selectedTask.id);
      done(accepted === jobIds.length
        ? `已投递 ${accepted} 个作业重试请求`
        : `已投递 ${accepted}/${jobIds.length} 个重试请求，其余被拒绝`);
      return true;
    } catch (caught) { busy = false; showError(caught); return false; }
  }
</script>

<svelte:head><title>{selectedProject ? `${selectedProject.name} · VulnWeaver` : "VulnWeaver · 漏洞织鉴"}</title></svelte:head>

{#if booting}
  <main class="boot" aria-busy="true"><div class="brand-mark">VW</div><p>正在恢复工作台</p></main>
{:else if !session}
  <AuthView mode="auth" {registrationOpen} {busy} {error} onSubmitLogin={login} onSubmitRegister={register} />
{:else if session.must_change_password}
  <AuthView mode="password" {busy} {error} onSubmitPassword={changePasswordFromGate} />
{:else}
  <div class="workspace">
    <header class="topbar">
      <button class="wordmark button-reset" on:click={goHome} title="回到默认页"><span>VW</span>VULNWEAVER</button>
      <div class="top-actions">
        <span class="system-state"><i></i>控制面在线</span>
        <span class="account">{session.username}</span>
        <button class="text-button" on:click={logout}>退出</button>
      </div>
    </header>
    <aside class="sidebar">
      <nav aria-label="主导航">
        <button class:active={view === "settings"} on:click={() => void openSettings()}>设置</button>
        <button class:active={view === "overview"} on:click={goOverview}>项目</button>
        {#if selectedProject}<button class:active={view === "project"} on:click={() => openProject(selectedProject!)}>样本与任务</button>{/if}
        {#if selectedTask}<button class:active={view === "task"} on:click={() => openTask(selectedTask!)}>执行轨迹</button>{/if}
      </nav>
      <div class="sidebar-note"><span>安全边界</span><p>动态执行只允许经策略校验后进入一次性沙箱。</p></div>
    </aside>
    <main class="content">
      {#if error}<div class="alert error global" role="alert"><span>{error}</span><button on:click={() => error = ""}>关闭</button></div>{/if}
      {#if notice}<div class="alert success global" role="status"><span>{notice}</span><button on:click={() => notice = ""}>关闭</button></div>{/if}

      {#if view === "settings" && productSettings}
        <SettingsView productSettings={productSettings} {busy} onSave={saveSettings} onUpdatePassword={updatePasswordFromSettings} />
      {:else if view === "overview"}
        <ProjectsView {projects} {busy} onOpenProject={openProject} onCreateProject={createProject} onShowError={(message) => (error = message)} />
      {:else if view === "project" && selectedProject}
        <ProjectView project={selectedProject} {artifacts} {artifactVersions} {tasks} {busy} onGoOverview={goOverview} onOpenTask={openTask} onUpload={upload} onCreateTask={createTask} onShowError={(message) => (error = message)} />
      {:else if view === "task" && selectedTask}
        <TaskView
          task={selectedTask}
          project={selectedProject}
          {jobs}
          {events}
          {findings}
          selectedFinding={selectedFinding}
          evidence={selectedEvidence}
          pocs={selectedPocs}
          reviews={selectedReviews}
          {agentRuns}
          {pairFunctions}
          {pairNeighborhood}
          {selectedFunctionId}
          {reportVersionIds}
          {artifactVersions}
          {taskType}
          {busy}
          onOpenProject={() => void openProject(selectedProject!)}
          onCancelTask={cancelTask}
          onRetryJobs={retryJobs}
          onCreateReport={createReport}
          onCreateProof={createProof}
          onSelectFinding={(finding) => void selectFinding(finding)}
          onSubmitReview={submitReview}
          onSubmitAnnotation={submitAnnotation}
          onSelectFunction={(fn) => void selectFunction(fn)}
        />
      {/if}
    </main>
  </div>
{/if}
