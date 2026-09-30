<script context="module" lang="ts">
  import type { ProductSettings } from "../api";

  export interface SettingsSavePayload {
    settings: ProductSettings;
    reviewApiKey: string;
    clearReviewApiKey: boolean;
    tierApiKeys: Record<string, string>;
    clearTierApiKeys: string[];
    providerApiKeys: Record<string, string>;
    clearProviderApiKeys: string[];
  }
</script>

<script lang="ts">
  import {
    PROVIDER_PRESETS,
    presetModelCatalog,
    type PresetModel,
    type ProviderPreset,
  } from "../providers";
  import { api, ApiError } from "../api";
  /** 产品设置页：模型供应商注册表、智能体绑定、工具镜像与运行时配置。 */

  type TierName = "planning" | "audit" | "review" | "report";
  type ModelProviderEntry = ProductSettings["model_providers"][number];
  type ProviderModelEntry = ModelProviderEntry["models"][number];

  export let productSettings: ProductSettings;
  export let busy = false;
  export let onSave: (payload: SettingsSavePayload) => Promise<boolean> = async () => false;
  export let onUpdatePassword: (currentPassword: string, newPassword: string) => Promise<boolean> = async () => false;

  const tierNames: TierName[] = ["planning", "audit", "review", "report"];
  const tierLabels: Record<TierName, string> = {
    planning: "规划智能体",
    audit: "语义审计智能体",
    review: "独立复核智能体",
    report: "报告智能体",
  };
  const apiFormatLabels: Record<ModelProviderEntry["api_format"], string> = {
    "openai-chat": "OpenAI 兼容（/chat/completions）",
    "anthropic-messages": "Anthropic Messages（/v1/messages）",
    "openai-responses": "OpenAI Responses（/responses）",
  };

  let reviewApiKey = "";
  let clearReviewApiKey = false;
  let tierApiKeys: Record<TierName, string> = { planning: "", audit: "", review: "", report: "" };
  let clearTierApiKeys: TierName[] = [];
  let providerApiKeys: Record<string, string> = {};
  let clearProviderApiKeys: string[] = [];
  let expandedProvider: string | null = null;
  let smartPicks: Record<string, string> = {};
  let probeNotes: Record<string, { message: string; ok: boolean }> = {};
  let showAdvancedSettings = false;

  const presetCatalog = presetModelCatalog();

  function providerKeyConfigured(providerId: string): boolean {
    return productSettings.providers_api_key_configured?.[providerId] ?? false;
  }

  function nextProviderId(base: string): string {
    const taken = new Set(productSettings.model_providers.map((p) => p.id));
    if (!taken.has(base)) return base;
    let index = 2;
    while (taken.has(`${base}-${index}`)) index += 1;
    return `${base}-${index}`;
  }

  function emptyProvider(id: string): ModelProviderEntry {
    return {
      id,
      name: "",
      base_url: "",
      api_format: "openai-chat",
      enabled: true,
      timeout_seconds: 0,
      max_attempts: 0,
      models: [],
    };
  }

  function addProvider(preset?: ProviderPreset): void {
    const id = nextProviderId(preset ? preset.id : `provider-${productSettings.model_providers.length + 1}`);
    const provider = emptyProvider(id);
    if (preset) {
      provider.name = preset.label;
      provider.base_url = preset.base_url;
      provider.api_format = preset.api_format;
      provider.models = preset.models.map((model) => ({
        model_id: model.model_id,
        display_name: model.note,
        context_window_tokens: model.context_window_tokens,
        max_output_tokens: model.max_output_tokens,
        thinking_mode: "off",
        thinking_budget_tokens: 0,
      }));
    }
    productSettings = {
      ...productSettings,
      model_providers: [...productSettings.model_providers, provider],
    };
    expandedProvider = id;
  }

  function removeProvider(providerId: string): void {
    productSettings = {
      ...productSettings,
      model_providers: productSettings.model_providers.filter((p) => p.id !== providerId),
    };
    productSettings = {
      ...productSettings,
      agent_model_bindings: clearBindingsFor(productSettings.agent_model_bindings, (b) =>
        b.provider_id === providerId ||
        b.fallback_provider_id === providerId),
    };
    delete providerApiKeys[providerId];
    delete smartPicks[providerId];
    delete probeNotes[providerId];
    clearProviderApiKeys = clearProviderApiKeys.filter((id) => id !== providerId);
    if (expandedProvider === providerId) expandedProvider = null;
  }

  function clearBindingsFor(
    bindings: ProductSettings["agent_model_bindings"],
    stale: (binding: NonNullable<ProductSettings["agent_model_bindings"][TierName]>) => boolean,
  ): ProductSettings["agent_model_bindings"] {
    const next = { ...bindings };
    for (const role of tierNames) {
      if (next[role] && stale(next[role]!)) next[role] = null;
    }
    return next;
  }

  function updateProvider(providerId: string, key: keyof ModelProviderEntry, value: unknown): void {
    productSettings = {
      ...productSettings,
      model_providers: productSettings.model_providers.map((provider) =>
        provider.id === providerId ? { ...provider, [key]: value } : provider,
      ),
    };
  }

  function addModel(providerId: string, preset?: PresetModel): void {
    const model: ProviderModelEntry = preset
      ? {
          model_id: preset.model_id,
          display_name: preset.note,
          context_window_tokens: preset.context_window_tokens,
          max_output_tokens: preset.max_output_tokens,
          thinking_mode: "off",
          thinking_budget_tokens: 0,
        }
      : { model_id: "", display_name: "", context_window_tokens: 0, max_output_tokens: 0, thinking_mode: "off", thinking_budget_tokens: 0 };
    productSettings = {
      ...productSettings,
      model_providers: productSettings.model_providers.map((provider) =>
        provider.id === providerId ? { ...provider, models: [...provider.models, model] } : provider,
      ),
    };
  }

  function updateModel(providerId: string, index: number, key: keyof ProviderModelEntry, value: unknown): void {
    productSettings = {
      ...productSettings,
      model_providers: productSettings.model_providers.map((provider) =>
        provider.id === providerId
          ? { ...provider, models: provider.models.map((m, i) => (i === index ? { ...m, [key]: value } : m)) }
          : provider,
      ),
    };
  }

  function removeModel(providerId: string, index: number): void {
    const removed = productSettings.model_providers.find((p) => p.id === providerId)?.models[index];
    productSettings = {
      ...productSettings,
      model_providers: productSettings.model_providers.map((provider) =>
        provider.id === providerId ? { ...provider, models: provider.models.filter((_, i) => i !== index) } : provider,
      ),
    };
    if (removed) {
      productSettings = {
        ...productSettings,
        agent_model_bindings: clearBindingsFor(productSettings.agent_model_bindings, (b) =>
          (b.provider_id === providerId && b.model_id === removed.model_id) ||
          (b.fallback_provider_id === providerId && b.fallback_model_id === removed.model_id)),
      };
    }
  }

  function toggleProviderKey(providerId: string, checked: boolean): void {
    if (checked) {
      if (!clearProviderApiKeys.includes(providerId)) clearProviderApiKeys = [...clearProviderApiKeys, providerId];
    } else {
      clearProviderApiKeys = clearProviderApiKeys.filter((id) => id !== providerId);
    }
  }

  async function probeModels(provider: ModelProviderEntry): Promise<void> {
    probeNotes = { ...probeNotes, [provider.id]: { message: "正在获取模型列表…", ok: true } };
    try {
      const supplied = providerApiKeys[provider.id]?.trim();
      const result = await api.probeProviderModels({
        provider_id: provider.id,
        base_url: provider.base_url,
        api_format: provider.api_format,
        ...(supplied ? { api_key: supplied } : {}),
      });
      if (result.error) {
        probeNotes = { ...probeNotes, [provider.id]: { message: result.error, ok: false } };
        return;
      }
      const existing = new Set(provider.models.map((m) => m.model_id));
      const additions: ProviderModelEntry[] = result.models
        .filter((modelId) => !existing.has(modelId))
        .map((modelId) => ({
          model_id: modelId,
          display_name: "",
          context_window_tokens: 0,
          max_output_tokens: 0,
          thinking_mode: "off",
          thinking_budget_tokens: 0,
        }));
      updateProvider(provider.id, "models", [...provider.models, ...additions]);
      probeNotes = {
        ...probeNotes,
        [provider.id]: { message: `获取到 ${result.models.length} 个模型，新增 ${additions.length} 个。`, ok: true },
      };
    } catch (caught) {
      const message = caught instanceof ApiError ? caught.message : "探测请求失败";
      probeNotes = { ...probeNotes, [provider.id]: { message, ok: false } };
    }
  }

  function bindingValue(role: TierName): string {
    const binding = productSettings.agent_model_bindings?.[role];
    return binding ? `${binding.provider_id}|${binding.model_id}` : "";
  }

  function fallbackValue(role: TierName): string {
    const binding = productSettings.agent_model_bindings?.[role];
    return binding?.fallback_provider_id && binding?.fallback_model_id
      ? `${binding.fallback_provider_id}|${binding.fallback_model_id}`
      : "";
  }

  function setBinding(role: TierName, raw: string, kind: "primary" | "fallback"): void {
    const bindings = { ...productSettings.agent_model_bindings };
    const current = bindings[role] ?? { provider_id: "", model_id: "" };
    if (!raw) {
      if (kind === "primary") {
        bindings[role] = null;
      } else {
        const cleared = { ...current };
        delete cleared.fallback_provider_id;
        delete cleared.fallback_model_id;
        bindings[role] = current.provider_id ? cleared : null;
      }
    } else {
      const [providerId, modelId] = raw.split("|");
      if (kind === "primary") {
        bindings[role] = { provider_id: providerId, model_id: modelId };
      } else {
        bindings[role] = {
          ...current,
          fallback_provider_id: providerId,
          fallback_model_id: modelId,
        };
      }
    }
    productSettings = { ...productSettings, agent_model_bindings: bindings };
  }

  function roleOptions(): Array<{ value: string; label: string }> {
    return productSettings.model_providers
      .filter((provider) => provider.enabled)
      .flatMap((provider) =>
        provider.models
          .filter((model) => model.model_id)
          .map((model) => ({ value: `${provider.id}|${model.model_id}`, label: `${provider.name || provider.id} / ${model.model_id}` })),
      );
  }

  let currentPassword = "";
  let newPassword = "";
  let confirmPassword = "";
  let passwordError = "";

  function toggleTierKey(tier: TierName, checked: boolean): void {
    if (checked) {
      if (!clearTierApiKeys.includes(tier)) clearTierApiKeys = [...clearTierApiKeys, tier];
    } else {
      clearTierApiKeys = clearTierApiKeys.filter((item) => item !== tier);
    }
  }

  async function save(): Promise<void> {
    if (!productSettings) return;
    const suppliedKeys: Record<string, string> = {};
    for (const tier of tierNames) {
      if (tierApiKeys[tier].trim()) suppliedKeys[tier] = tierApiKeys[tier].trim();
    }
    const suppliedProviderKeys: Record<string, string> = {};
    for (const [providerId, value] of Object.entries(providerApiKeys)) {
      if (value.trim()) suppliedProviderKeys[providerId] = value.trim();
    }
    const saved = await onSave({
      settings: productSettings,
      reviewApiKey: reviewApiKey,
      clearReviewApiKey: clearReviewApiKey,
      tierApiKeys: suppliedKeys,
      clearTierApiKeys: [...clearTierApiKeys],
      providerApiKeys: suppliedProviderKeys,
      clearProviderApiKeys: [...clearProviderApiKeys],
    });
    if (saved) {
      reviewApiKey = "";
      clearReviewApiKey = false;
      tierApiKeys = { planning: "", audit: "", review: "", report: "" };
      clearTierApiKeys = [];
      providerApiKeys = {};
      clearProviderApiKeys = [];
    }
  }

  async function updatePassword(): Promise<void> {
    if (newPassword !== confirmPassword) {
      passwordError = "两次输入的新密码不一致";
      return;
    }
    passwordError = "";
    const saved = await onUpdatePassword(currentPassword, newPassword);
    if (saved) currentPassword = newPassword = confirmPassword = "";
  }
</script>

<section class="page-heading">
  <div>
    <h1>产品设置</h1>
    <p>配置审计使用的模型与工具。保存后，新执行的任务将使用最新设置。</p>
  </div>
</section>
<div class="settings-layout">
  <nav class="settings-rail" aria-label="设置分区">
    <a href="#sec-model-providers">模型供应商</a>
    <a href="#sec-agent-bindings">智能体模型绑定</a>
    <a href="#sec-tool-images">工具镜像</a>
    <a href="#sec-sandbox-budgets">高级设置</a>
    <a href="#sec-account">账户安全</a>
  </nav>
  <div class="settings-body">
    <form class="settings-form" on:submit|preventDefault={save}>
      <section class="panel" id="sec-model-providers">
        <header class="panel-head">
          <div>
            <h2>模型供应商</h2>
            <p>每个供应商承载一条连接（Base URL、API 格式、API Key）与自己的模型列表；开关关闭的供应商不参与调用。</p>
          </div>
          <button type="button" class="secondary" on:click={() => addProvider()}>+ 添加供应商</button>
        </header>
        <div class="preset-row" role="group" aria-label="供应商预设">
          <span class="preset-label">从预设创建</span>
          {#each PROVIDER_PRESETS as preset (preset.id)}
            <button type="button" class="preset-chip" on:click={() => addProvider(preset)}>{preset.label}</button>
          {/each}
          <button type="button" class="preset-chip" on:click={() => addProvider()}>自定义</button>
        </div>
        {#if productSettings.model_providers.length === 0}
          <p class="muted">当前没有配置供应商。从上方预设一键创建，或手动添加供应商后，把模型绑定给各个智能体。</p>
        {/if}
        <div class="tier-list">
          {#each productSettings.model_providers as provider (provider.id)}
            <div class="tier-group" class:open={expandedProvider === provider.id}>
              <button type="button" class="tier-toggle" aria-expanded={expandedProvider === provider.id} on:click={() => (expandedProvider = expandedProvider === provider.id ? null : provider.id)}>
                <b>{provider.name || provider.id}</b>
                <span class="tier-state" class:enabled={provider.enabled && provider.models.length > 0}>
                  {provider.enabled ? `${apiFormatLabels[provider.api_format]} · ${provider.models.length} 个模型` : "已停用"}
                </span>
                <span class="arrow" aria-hidden="true">▾</span>
              </button>
              {#if expandedProvider === provider.id}
                <div class="tier-body">
                  <div class="field-grid">
                    <label>供应商 ID<small class="muted">（创建后不可改）</small><input value={provider.id} disabled /></label>
                    <label>显示名称<input value={provider.name} on:change={(e) => updateProvider(provider.id, "name", e.currentTarget.value)} placeholder="例如 DeepSeek 官方" /></label>
                    <label>Base URL<input value={provider.base_url} on:change={(e) => updateProvider(provider.id, "base_url", e.currentTarget.value)} placeholder="https://api.example.com/v1" /></label>
                    <label>API 格式<select value={provider.api_format} on:change={(e) => updateProvider(provider.id, "api_format", e.currentTarget.value)}>
                      {#each Object.entries(apiFormatLabels) as [format, label] (format)}<option value={format}>{label}</option>{/each}
                    </select></label>
                    <label>API Key<input value={providerApiKeys[provider.id] ?? ""} on:input={(e) => (providerApiKeys = { ...providerApiKeys, [provider.id]: e.currentTarget.value })} type="password" autocomplete="new-password" placeholder={providerKeyConfigured(provider.id) ? "留空以保留现有值" : "输入 API Key"} /></label>
                    <label class="check"><input type="checkbox" checked={provider.enabled} on:change={(e) => updateProvider(provider.id, "enabled", e.currentTarget.checked)} /><span><b>启用该供应商</b></span></label>
                  </div>
                  {#if providerKeyConfigured(provider.id)}
                    <label class="check"><input type="checkbox" checked={clearProviderApiKeys.includes(provider.id)} on:change={(e) => toggleProviderKey(provider.id, e.currentTarget.checked)} /><span><b>清除该供应商已保存的 API Key</b></span></label>
                  {/if}
                  <div class="model-head">
                    <b>模型列表</b>
                    <span class="model-head-actions">
                      <select on:change={(e) => { const pick = presetCatalog.find((p) => `${p.provider}::${p.model.model_id}` === e.currentTarget.value); if (pick) { addModel(provider.id, pick.model); e.currentTarget.value = ""; } }}>
                        <option value="">+ 智能配置（从预置目录选模型）</option>
                        {#each presetCatalog as entry (entry.provider + entry.model.model_id)}
                          <option value={`${entry.provider}::${entry.model.model_id}`}>{entry.provider} · {entry.model.model_id}（上下文 {entry.model.context_window_tokens} / 输出 {entry.model.max_output_tokens}）</option>
                        {/each}
                      </select>
                      <button type="button" class="secondary" on:click={() => addModel(provider.id)}>+ 手动添加模型</button>
                      <button type="button" class="secondary" disabled={busy} on:click={() => probeModels(provider)}>获取模型列表</button>
                    </span>
                  </div>
                  {#if probeNotes[provider.id]}<p class="muted" class:probe-error={!probeNotes[provider.id].ok}>{probeNotes[provider.id].message}</p>{/if}
                  {#if provider.models.length === 0}
                    <p class="muted">当前没有配置模型，添加模型后才能绑定给智能体使用。</p>
                  {:else}
                    <div class="model-table">
                      {#each provider.models as model, mIndex (mIndex)}
                        <div class="model-row">
                          <label>模型 ID<input value={model.model_id} on:change={(e) => updateModel(provider.id, mIndex, "model_id", e.currentTarget.value)} placeholder="model-id" /></label>
                          <label>上下文窗口（token，0=默认）<input value={model.context_window_tokens ?? 0} on:change={(e) => updateModel(provider.id, mIndex, "context_window_tokens", Number(e.currentTarget.value))} type="number" min="0" /></label>
                          <label>最大输出（token，0=默认）<input value={model.max_output_tokens ?? 0} on:change={(e) => updateModel(provider.id, mIndex, "max_output_tokens", Number(e.currentTarget.value))} type="number" min="0" /></label>
                          <label>思考模式<select value={model.thinking_mode ?? "off"} on:change={(e) => updateModel(provider.id, mIndex, "thinking_mode", e.currentTarget.value)}>
                            <option value="off">关闭</option>
                            <option value="default">开启（供应商默认预算）</option>
                            <option value="custom">自定义预算</option>
                          </select></label>
                          {#if model.thinking_mode === "custom"}
                            <label>思考预算（token，≥1024）<input value={model.thinking_budget_tokens ?? 0} on:change={(e) => updateModel(provider.id, mIndex, "thinking_budget_tokens", Number(e.currentTarget.value))} type="number" min="1024" /></label>
                          {/if}
                          <button type="button" class="secondary model-remove" on:click={() => removeModel(provider.id, mIndex)}>删除</button>
                        </div>
                      {/each}
                    </div>
                  {/if}
                  <div class="field-grid cols-4">
                    <label>单次请求超时（秒，0=全局默认）<input value={provider.timeout_seconds ?? 0} on:change={(e) => updateProvider(provider.id, "timeout_seconds", Number(e.currentTarget.value))} type="number" min="0" max="3600" /></label>
                    <label>最大尝试（0=全局默认）<input value={provider.max_attempts ?? 0} on:change={(e) => updateProvider(provider.id, "max_attempts", Number(e.currentTarget.value))} type="number" min="0" max="8" /></label>
                  </div>
                  <button type="button" class="secondary provider-delete" on:click={() => removeProvider(provider.id)}>删除该供应商</button>
                </div>
              {/if}
            </div>
          {/each}
        </div>
      </section>

      <section class="panel" id="sec-agent-bindings">
        <header class="panel-head">
          <div>
            <h2>智能体模型绑定</h2>
            <p>为每个智能体选择一个供应商模型，可另配备用模型；主模型调用失败且可重试时自动切换备用。未绑定的智能体无法使用模型。</p>
          </div>
        </header>
        <div class="binding-list">
          {#each tierNames as role (role)}
            <div class="binding-row">
              <b>{tierLabels[role]}</b>
              <label>主模型<select value={bindingValue(role)} on:change={(e) => setBinding(role, e.currentTarget.value, "primary")}>
                <option value="">未绑定</option>
                {#each roleOptions() as option (option.value)}<option value={option.value}>{option.label}</option>{/each}
              </select></label>
              <label>备用模型<select value={fallbackValue(role)} on:change={(e) => setBinding(role, e.currentTarget.value, "fallback")}>
                <option value="">无</option>
                {#each roleOptions() as option (option.value)}<option value={option.value}>{option.label}</option>{/each}
              </select></label>
            </div>
          {/each}
        </div>
      </section>

      <section class="panel" id="sec-tool-images">
        <header class="panel-head">
          <div><h2>工具镜像登记</h2><p>固定摘要优先；留空时由 Runner 自动发现端点或本地镜像。</p></div>
        </header>
        <div class="stack-list">
          <label>binary-tools 摘要（Ghidra / 关键逻辑 / 调用路径）<input bind:value={productSettings.tool_image_digests.binary_tools} placeholder="sha256:…（留空自动发现）" /></label>
          <label>proof-tool 摘要（自动利用 / Proof）<input bind:value={productSettings.tool_image_digests.proof_tool} placeholder="sha256:…（留空自动发现）" /></label>
          <label>afl-casr 摘要（模糊测试 / Harness 编译）<input bind:value={productSettings.tool_image_digests.afl_casr} placeholder="sha256:…（留空自动发现）" /></label>
        </div>
        <div class="capability-strip" aria-label="执行能力状态">
          <span class:enabled={!!productSettings.tool_image_digests.binary_tools}><i></i>二进制管线</span>
          <span class:enabled={!!productSettings.tool_image_digests.proof_tool}><i></i>Proof / 自动利用</span>
          <span class:enabled={!!productSettings.tool_image_digests.afl_casr}><i></i>模糊测试</span>
          <span class:enabled={productSettings.model_providers.some((p) => p.enabled && p.models.length > 0)}><i></i>模型分析</span>
        </div>
      </section>

      <div class="advanced-anchor" id="sec-sandbox-budgets">
        <button type="button" class="secondary adv-toggle" aria-expanded={showAdvancedSettings} on:click={() => showAdvancedSettings = !showAdvancedSettings}>{showAdvancedSettings ? "收起高级设置" : "高级设置：模糊测试与运行时"}</button>
        {#if showAdvancedSettings}
          <section class="panel advanced-settings">
            <p class="muted">0 表示未设置，沿用环境变量或代码默认值；更改在下一次任务执行时生效。智能体循环没有 token 配额，墙钟超时是唯一兜底。</p>
            <div class="field-grid cols-4">
              <label>Fuzz 最大执行次数<input bind:value={productSettings.fuzz_budgets.max_executions} type="number" min="0" /></label>
              <label>Fuzz 最长时长（秒）<input bind:value={productSettings.fuzz_budgets.max_duration_seconds} type="number" min="0" max="86400" /></label>
              <label>Fuzz 崩溃上限<input bind:value={productSettings.fuzz_budgets.max_crashes} type="number" min="0" max="10000" /></label>
            </div>
            <div class="field-grid">
              <label>审计智能体超时（秒，默认 8 小时）<input bind:value={productSettings.agent_loop_budgets.audit_deadline_seconds} type="number" min="0" max="604800" /></label>
              <label>逆向规划智能体超时（秒，默认 2 小时）<input bind:value={productSettings.agent_loop_budgets.reverse_planning_deadline_seconds} type="number" min="0" max="604800" /></label>
            </div>
            <div class="field-grid">
              <label>Sandbox Runner 超时（秒）<input bind:value={productSettings.sandbox_runner_timeout_seconds} type="number" min="0" max="86400" /></label>
              <label>Fuzz Runner 超时（秒）<input bind:value={productSettings.fuzz_runner_timeout_seconds} type="number" min="0" max="86400" /></label>
            </div>
            <label class="check"><input type="checkbox" checked={productSettings.angr_enabled ?? false} on:change={(e) => (productSettings.angr_enabled = e.currentTarget.checked ? true : null)} /><span><b>启用 angr 符号执行</b><small>仅在二进制沙箱可用时实际生效；关闭时回退环境变量。</small></span></label>
          </section>
        {/if}
      </div>
      <div class="form-actions"><button class="primary" disabled={busy}>保存设置</button></div>
    </form>

    <form class="panel account-panel" id="sec-account" on:submit|preventDefault={updatePassword}>
      <header class="panel-head">
        <div><h2>更改密码</h2><p>成功后保留当前会话并撤销其他会话。</p></div>
      </header>
      {#if passwordError}<div class="alert error" role="alert">{passwordError}</div>{/if}
      <label class="stack-list">当前密码<input bind:value={currentPassword} type="password" autocomplete="current-password" required /></label>
      <div class="field-grid">
        <label>新密码<input bind:value={newPassword} type="password" minlength="12" autocomplete="new-password" required /></label>
        <label>确认新密码<input bind:value={confirmPassword} type="password" minlength="12" autocomplete="new-password" required /></label>
      </div>
      <div class="form-actions"><button class="primary" disabled={busy}>更新密码</button></div>
    </form>
  </div>
</div>

<style>
  /* 供应商卡片与模型行：复用设置页既有面板风格，补充少量局部布局。 */
  .model-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.75rem;
    margin: 0.75rem 0 0.5rem;
  }
  .model-head-actions {
    display: flex;
    gap: 0.5rem;
    align-items: center;
  }
  .model-table {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }
  .model-row {
    display: grid;
    grid-template-columns: minmax(180px, 1.4fr) 1fr 1fr 1fr auto;
    gap: 0.5rem;
    align-items: end;
    border: 1px solid var(--border, #e2e2e2);
    border-radius: 8px;
    padding: 0.5rem;
  }
  .model-remove {
    height: fit-content;
  }
  .probe-error {
    color: var(--danger, #b3261e);
  }
  .provider-delete {
    margin-top: 0.75rem;
  }
  .binding-list {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }
  .binding-row {
    display: grid;
    grid-template-columns: 10rem minmax(200px, 1fr) minmax(200px, 1fr);
    gap: 0.75rem;
    align-items: center;
  }
</style>
