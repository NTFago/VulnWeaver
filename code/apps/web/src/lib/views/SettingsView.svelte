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
  import { fade, fly } from "svelte/transition";
  import { PROVIDER_PRESETS, presetModelCatalog, type PresetModel, type ProviderPreset } from "../providers";
  import { api, ApiError } from "../api";
  /**
   * 产品设置页：模型供应商（卡片 + 模型列表 + 添加模型弹窗）、智能体绑定、
   * 工具镜像与运行时配置。表单字段状态在本组件维护。
   */

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
  const apiFormatShort: Record<ModelProviderEntry["api_format"], string> = {
    "openai-chat": "OpenAI 兼容",
    "anthropic-messages": "Anthropic",
    "openai-responses": "Responses",
  };

  const presetCatalog = presetModelCatalog();

  let reviewApiKey = "";
  let clearReviewApiKey = false;
  let tierApiKeys: Record<TierName, string> = { planning: "", audit: "", review: "", report: "" };
  let clearTierApiKeys: TierName[] = [];
  let providerApiKeys: Record<string, string> = {};
  let clearProviderApiKeys: string[] = [];
  let expandedProvider: string | null = null;
  let keyVisibility: Record<string, boolean> = {};
  let probeNotes: Record<string, { message: string; ok: boolean }> = {};
  let showAdvancedSettings = false;

  /* 添加/编辑模型弹窗状态；index 为 null 表示新增。 */
  let modelDialog: {
    providerId: string;
    index: number | null;
    draft: ProviderModelEntry;
    smart: boolean;
    smartPick: string;
  } | null = null;

  function emptyModel(): ProviderModelEntry {
    return {
      model_id: "",
      display_name: "",
      context_window_tokens: 0,
      max_output_tokens: 0,
      thinking_mode: "off",
      thinking_budget_tokens: 0,
    };
  }

  function openAddModel(provider: ModelProviderEntry): void {
    modelDialog = { providerId: provider.id, index: null, draft: emptyModel(), smart: false, smartPick: "" };
  }

  function openEditModel(provider: ModelProviderEntry, index: number): void {
    modelDialog = {
      providerId: provider.id,
      index,
      draft: { ...provider.models[index] },
      smart: false,
      smartPick: "",
    };
  }

  function closeModelDialog(): void {
    modelDialog = null;
  }

  function applySmartPick(raw: string): void {
    if (!modelDialog) return;
    modelDialog.smartPick = raw;
    const pick = presetCatalog.find((entry) => `${entry.provider}::${entry.model.model_id}` === raw);
    if (!pick) return;
    modelDialog.draft = {
      ...modelDialog.draft,
      model_id: pick.model.model_id,
      display_name: pick.model.note,
      context_window_tokens: pick.model.context_window_tokens,
      max_output_tokens: pick.model.max_output_tokens,
    };
  }

  function submitModelDialog(): void {
    if (!modelDialog) return;
    const draft = { ...modelDialog.draft, model_id: modelDialog.draft.model_id.trim() };
    if (!draft.model_id) return;
    const provider = productSettings.model_providers.find((p) => p.id === modelDialog!.providerId);
    if (!provider) return;
    const models = [...provider.models];
    if (modelDialog.index === null) {
      models.push(draft);
    } else {
      models[modelDialog.index] = draft;
    }
    updateProvider(modelDialog.providerId, "models", models);
    modelDialog = null;
  }

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

  function addProvider(preset?: ProviderPreset): void {
    const id = nextProviderId(preset ? preset.id : `provider-${productSettings.model_providers.length + 1}`);
    const provider: ModelProviderEntry = {
      id,
      name: preset ? preset.label : "",
      base_url: preset ? preset.base_url : "",
      api_format: preset ? preset.api_format : "openai-chat",
      enabled: true,
      timeout_seconds: 0,
      max_attempts: 0,
      models: preset
        ? preset.models.map((model) => ({
            model_id: model.model_id,
            display_name: model.note,
            context_window_tokens: model.context_window_tokens,
            max_output_tokens: model.max_output_tokens,
            thinking_mode: "off",
            thinking_budget_tokens: 0,
          }))
        : [],
    };
    productSettings = {
      ...productSettings,
      model_providers: [...productSettings.model_providers, provider],
    };
    expandedProvider = id;
  }

  function clearBindingsWhere(stale: (binding: NonNullable<ProductSettings["agent_model_bindings"][TierName]>) => boolean): void {
    const next = { ...productSettings.agent_model_bindings };
    for (const role of tierNames) {
      if (next[role] && stale(next[role]!)) next[role] = null;
    }
    productSettings = { ...productSettings, agent_model_bindings: next };
  }

  function removeProvider(providerId: string): void {
    productSettings = {
      ...productSettings,
      model_providers: productSettings.model_providers.filter((p) => p.id !== providerId),
    };
    clearBindingsWhere(
      (b) => b.provider_id === providerId || b.fallback_provider_id === providerId,
    );
    delete providerApiKeys[providerId];
    delete keyVisibility[providerId];
    delete probeNotes[providerId];
    clearProviderApiKeys = clearProviderApiKeys.filter((id) => id !== providerId);
    if (expandedProvider === providerId) expandedProvider = null;
  }

  function updateProvider(providerId: string, key: keyof ModelProviderEntry, value: unknown): void {
    productSettings = {
      ...productSettings,
      model_providers: productSettings.model_providers.map((provider) =>
        provider.id === providerId ? { ...provider, [key]: value } : provider,
      ),
    };
  }

  function removeModel(providerId: string, index: number): void {
    const provider = productSettings.model_providers.find((p) => p.id === providerId);
    if (!provider) return;
    const removed = provider.models[index];
    updateProvider(providerId, "models", provider.models.filter((_, i) => i !== index));
    if (removed) {
      clearBindingsWhere(
        (b) =>
          (b.provider_id === providerId && b.model_id === removed.model_id) ||
          (b.fallback_provider_id === providerId && b.fallback_model_id === removed.model_id),
      );
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
      const additions = result.models
        .filter((modelId) => !existing.has(modelId))
        .map((modelId) => ({ ...emptyModel(), model_id: modelId }));
      updateProvider(provider.id, "models", [...provider.models, ...additions]);
      probeNotes = {
        ...probeNotes,
        [provider.id]: {
          message: additions.length ? `获取到 ${result.models.length} 个模型，已合并新增 ${additions.length} 个。` : "模型列表已是最新。",
          ok: true,
        },
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
        bindings[role] = { ...current, fallback_provider_id: providerId, fallback_model_id: modelId };
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
          .map((model) => ({
            value: `${provider.id}|${model.model_id}`,
            label: `${provider.name || provider.id} / ${model.model_id}`,
          })),
      );
  }

  function tokenLabel(value: number | undefined): string {
    const tokens = value ?? 0;
    if (!tokens) return "默认";
    if (tokens >= 4096) return `${Math.round(tokens / 1024)}K`;
    return String(tokens);
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

  function dialogAutofocus(node: HTMLInputElement): void {
    node.focus();
  }
</script>

<svelte:window on:keydown={(e) => { if (e.key === "Escape" && modelDialog) closeModelDialog(); }} />

<section class="page-heading">
  <div>
    <h1>产品设置</h1>
    <p>保存后，新任务使用新配置。</p>
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
            <p>开关关闭的供应商不参与调用。</p>
          </div>
          <button type="button" class="secondary" on:click={() => addProvider()}>＋ 新供应商</button>
        </header>

        <div class="preset-row" role="group" aria-label="供应商预设">
          <span class="preset-label">从预设创建</span>
          {#each PROVIDER_PRESETS as preset (preset.id)}
            <button type="button" class="preset-chip" on:click={() => addProvider(preset)}>{preset.label}</button>
          {/each}
        </div>

        {#if productSettings.model_providers.length === 0}
          <div class="provider-empty">
            <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M21 8l-9-5-9 5v8l9 5 9-5V8zm-9-2.7L18.6 8 12 11.7 5.4 8 12 5.3zM5 9.7l6 3.4v6.2l-6-3.3V9.7zm8 9.6v-6.2l6-3.4v6.3l-6 3.3z"/></svg>
            <p>从上方预设一键创建，或手动添加。</p>
          </div>
        {:else}
          <div class="provider-list">
            {#each productSettings.model_providers as provider (provider.id)}
              {@const expanded = expandedProvider === provider.id}
              <article class="provider-card" class:open={expanded} class:off={!provider.enabled}>
                <header class="provider-head">
                  <button
                    type="button"
                    class="provider-disclose"
                    aria-expanded={expanded}
                    on:click={() => (expandedProvider = expanded ? null : provider.id)}
                  >
                    <svg class="provider-glyph" viewBox="0 0 24 24" aria-hidden="true"><path d="M21 8l-9-5-9 5v8l9 5 9-5V8zm-9-2.7L18.6 8 12 11.7 5.4 8 12 5.3zM5 9.7l6 3.4v6.2l-6-3.3V9.7zm8 9.6v-6.2l6-3.4v6.3l-6 3.3z"/></svg>
                    <span class="provider-name">{provider.name || provider.id}</span>
                    <span class="provider-id">{provider.id}</span>
                    <span class="badge muted">{apiFormatShort[provider.api_format]}</span>
                    <span class="provider-meta">
                      {provider.enabled ? `${provider.models.length} 个模型` : "已停用"}
                    </span>
                    <svg class="provider-arrow" viewBox="0 0 24 24" aria-hidden="true"><path d="M7 10l5 5 5-5z"/></svg>
                  </button>
                  <label class="switch" data-tip={provider.enabled ? "停用该供应商" : "启用该供应商"}>
                    <input type="checkbox" checked={provider.enabled} on:change={(e) => updateProvider(provider.id, "enabled", e.currentTarget.checked)} />
                    <span class="switch-track" aria-hidden="true"><span class="switch-thumb"></span></span>
                    <span class="sr-only">启用 {provider.name || provider.id}</span>
                  </label>
                </header>

                {#if expanded}
                  <div class="provider-body" transition:fade={{ duration: 120 }}>
                    <div class="provider-fields">
                      <label>显示名称
                        <input value={provider.name} on:change={(e) => updateProvider(provider.id, "name", e.currentTarget.value)} placeholder="例如 DeepSeek 官方" />
                      </label>
                      <label>Base URL
                        <input class="mono" value={provider.base_url} on:change={(e) => updateProvider(provider.id, "base_url", e.currentTarget.value)} placeholder="https://api.example.com/v1" />
                      </label>
                      <label>API 格式
                        <select value={provider.api_format} on:change={(e) => updateProvider(provider.id, "api_format", e.currentTarget.value)}>
                          {#each Object.entries(apiFormatLabels) as [format, label] (format)}<option value={format}>{label}</option>{/each}
                        </select>
                      </label>
                      <label>API Key
                        <span class="key-input">
                          <input
                            class="mono"
                            type={keyVisibility[provider.id] ? "text" : "password"}
                            value={providerApiKeys[provider.id] ?? ""}
                            on:input={(e) => (providerApiKeys = { ...providerApiKeys, [provider.id]: e.currentTarget.value })}
                            autocomplete="new-password"
                            placeholder={providerKeyConfigured(provider.id) ? "留空以保留现有值" : "输入 API Key"}
                          />
                          <button
                            type="button"
                            class="key-eye"
                            aria-label={keyVisibility[provider.id] ? "隐藏 API Key" : "显示 API Key"}
                            on:click={() => (keyVisibility = { ...keyVisibility, [provider.id]: !keyVisibility[provider.id] })}
                          >
                            {#if keyVisibility[provider.id]}
                              <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 6a9.8 9.8 0 018.8 5.5 1 1 0 010 .9A9.8 9.8 0 0112 18a9.8 9.8 0 01-8.8-5.5 1 1 0 010-.9A9.8 9.8 0 0112 6zm0 2.2a3.3 3.3 0 100 6.6 3.3 3.3 0 000-6.6z"/></svg>
                            {:else}
                              <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M2.1 3.5l1.3-1.2 17.5 18.2-1.3 1.2-3-3.1A10.7 10.7 0 0112 20a9.8 9.8 0 01-8.8-5.5 1 1 0 010-.9 10 10 0 013.7-4L2.1 3.5zM12 6c1.4 0 2.8.3 4 .9l-1.6 1.6a3.3 3.3 0 00-4.4 4.4l-1.9-2A3.3 3.3 0 0112 8.2zm0-2a9.8 9.8 0 018.8 5.5 1 1 0 010 .9 10.3 10.3 0 01-2.4 3l-1.5-1.5A8.2 8.2 0 0018.7 10 7.8 7.8 0 0012 6z"/></svg>
                            {/if}
                          </button>
                        </span>
                        <small class="field-note">
                          {providerKeyConfigured(provider.id)
                            ? (clearProviderApiKeys.includes(provider.id) ? "保存后删除已存密钥。" : "已配置。勾选下方可清除。")
                            : "未配置。"}
                        </small>
                      </label>
                      {#if providerKeyConfigured(provider.id)}
                        <label class="check key-clear">
                          <input type="checkbox" checked={clearProviderApiKeys.includes(provider.id)} on:change={(e) => toggleProviderKey(provider.id, e.currentTarget.checked)} />
                          <span><b>清除已保存的 API Key</b></span>
                        </label>
                      {/if}
                      <div class="provider-advanced">
                        <label>单次请求超时（秒，0=全局默认）
                          <input class="mono" value={provider.timeout_seconds ?? 0} on:change={(e) => updateProvider(provider.id, "timeout_seconds", Number(e.currentTarget.value))} type="number" min="0" max="3600" />
                        </label>
                        <label>最大尝试（0=全局默认）
                          <input class="mono" value={provider.max_attempts ?? 0} on:change={(e) => updateProvider(provider.id, "max_attempts", Number(e.currentTarget.value))} type="number" min="0" max="8" />
                        </label>
                      </div>
                    </div>

                    <div class="model-section">
                      <header class="model-section-head">
                        <b>模型列表</b>
                        <span class="model-count">{provider.models.length ? `${provider.models.length} 个模型` : ""}</span>
                        <span class="model-section-actions">
                          <button type="button" class="text-button" disabled={busy} on:click={() => probeModels(provider)}>获取模型列表</button>
                          <button type="button" class="add-model" on:click={() => openAddModel(provider)}>＋ 添加模型</button>
                        </span>
                      </header>

                      {#if probeNotes[provider.id]}
                        <p class="probe-note" class:bad={!probeNotes[provider.id].ok}>{probeNotes[provider.id].message}</p>
                      {/if}

                      {#if provider.models.length === 0}
                        <div class="model-empty">
                          <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 2a10 10 0 100 20 10 10 0 000-20zm0 4.2a1.2 1.2 0 110 2.4 1.2 1.2 0 010-2.4zM11 10h2v7h-2v-7z"/></svg>
                          <p>添加模型后才能绑定给智能体。</p>
                        </div>
                      {:else}
                        <ul class="model-list">
                          {#each provider.models as model, mIndex (mIndex)}
                            <li class="model-item">
                              <div class="model-id">
                                {#if model.model_id}<span class="mono">{model.model_id}</span>{:else}<span class="mono"><em>未命名模型</em></span>{/if}
                                {#if model.display_name}<span class="model-display">{model.display_name}</span>{/if}
                              </div>
                              <div class="model-tags">
                                <span class="tag" data-tip="上下文窗口（Token）；0 表示交由供应商默认">上下文 {tokenLabel(model.context_window_tokens)}</span>
                                <span class="tag" data-tip="单次回复输出上限（Token）；0 表示交由供应商默认">输出 {tokenLabel(model.max_output_tokens)}</span>
                                {#if model.thinking_mode !== "off"}
                                  <span class="tag accent" data-tip="扩展思考">思考{model.thinking_mode === "custom" ? ` ${Math.round((model.thinking_budget_tokens || 0) / 1024)}K` : ""}</span>
                                {/if}
                              </div>
                              <div class="model-actions">
                                <button type="button" class="text-button" on:click={() => openEditModel(provider, mIndex)}>编辑</button>
                                <button type="button" class="text-button danger-text" on:click={() => removeModel(provider.id, mIndex)}>删除</button>
                              </div>
                            </li>
                          {/each}
                        </ul>
                      {/if}
                    </div>

                    <footer class="provider-foot">
                      <button type="button" class="text-button danger-text" on:click={() => removeProvider(provider.id)}>删除该供应商</button>
                    </footer>
                  </div>
                {/if}
              </article>
            {/each}
          </div>
        {/if}
      </section>

      <section class="panel" id="sec-agent-bindings">
        <header class="panel-head">
          <div>
            <h2>智能体模型绑定</h2>
            <p>主模型失败时自动切换备用模型；未绑定的智能体不调用模型。</p>
          </div>
        </header>
        <div class="binding-list">
          {#each tierNames as role (role)}
            <div class="binding-row">
              <b>{tierLabels[role]}</b>
              <label>主模型
                <select value={bindingValue(role)} on:change={(e) => setBinding(role, e.currentTarget.value, "primary")}>
                  <option value="">未绑定</option>
                  {#each roleOptions() as option (option.value)}<option value={option.value}>{option.label}</option>{/each}
                </select>
              </label>
              <label>备用模型
                <select value={fallbackValue(role)} on:change={(e) => setBinding(role, e.currentTarget.value, "fallback")}>
                  <option value="">无</option>
                  {#each roleOptions() as option (option.value)}<option value={option.value}>{option.label}</option>{/each}
                </select>
              </label>
            </div>
          {/each}
        </div>
      </section>

      <section class="panel" id="sec-tool-images">
        <header class="panel-head">
          <div><h2>工具镜像登记</h2><p>固定摘要优先，留空自动发现。</p></div>
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
            <p class="muted">0 表示沿用默认值；更改在下次任务生效。</p>
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

{#if modelDialog}
  <div class="dialog-backdrop" transition:fade={{ duration: 120 }} on:click|self={closeModelDialog} role="presentation">
    <div class="dialog" role="dialog" aria-modal="true" aria-label={modelDialog.index === null ? "添加模型" : "编辑模型"} transition:fly={{ y: 14, duration: 160 }}>
      <header class="dialog-head">
        <h3>{modelDialog.index === null ? "添加模型" : "编辑模型"}</h3>
        <button type="button" class="text-button dialog-close" aria-label="关闭" on:click={closeModelDialog}>✕</button>
      </header>

      <label class="check dialog-smart">
        <input type="checkbox" bind:checked={modelDialog.smart} />
        <span><b>智能配置</b><small>从预设带入模型 ID 与推荐参数，可再修改。</small></span>
      </label>
      {#if modelDialog.smart}
        <label class="dialog-field">从预设选择
          <select value={modelDialog.smartPick} on:change={(e) => applySmartPick(e.currentTarget.value)}>
            <option value="">选择预设模型…</option>
            {#each presetCatalog as entry (entry.provider + entry.model.model_id)}
              <option value={`${entry.provider}::${entry.model.model_id}`}>
                {entry.provider} · {entry.model.model_id}（上下文 {tokenLabel(entry.model.context_window_tokens)} / 输出 {tokenLabel(entry.model.max_output_tokens)}）
              </option>
            {/each}
          </select>
        </label>
      {/if}

      <label class="dialog-field">模型 ID
        <input class="mono" bind:value={modelDialog.draft.model_id} use:dialogAutofocus placeholder="model-id" />
      </label>
      <label class="dialog-field">显示名称（可选）
        <input bind:value={modelDialog.draft.display_name} placeholder="例如 通用对话，指向最新 V 系列" />
      </label>
      <div class="dialog-cols">
        <label class="dialog-field">上下文窗口
          <span class="tip-anchor">
            <input class="mono" bind:value={modelDialog.draft.context_window_tokens} type="number" min="0" placeholder="0" />
            <span class="tip-mark" data-tip="模型一次可处理的上下文容量，单位为 Token；网关据此自动裁剪超长输入。请勿超过模型的实际上限。0 表示交由供应商默认。">?</span>
          </span>
        </label>
        <label class="dialog-field">最大输出 Tokens
          <span class="tip-anchor">
            <input class="mono" bind:value={modelDialog.draft.max_output_tokens} type="number" min="0" placeholder="0" />
            <span class="tip-mark" data-tip="单次回复的输出上限，单位为 Token；决定 Anthropic max_tokens 缺省与上下文预留。0 表示交由供应商默认。">?</span>
          </span>
        </label>
      </div>
      <div class="dialog-cols">
        <label class="dialog-field">思考模式
          <select bind:value={modelDialog.draft.thinking_mode}>
            <option value="off">关闭</option>
            <option value="default">开启（供应商默认预算）</option>
            <option value="custom">自定义预算</option>
          </select>
        </label>
        {#if modelDialog.draft.thinking_mode === "custom"}
          <label class="dialog-field">思考预算（Token，≥1024）
            <input class="mono" bind:value={modelDialog.draft.thinking_budget_tokens} type="number" min="1024" />
          </label>
        {/if}
      </div>

      <footer class="dialog-foot">
        <button type="button" class="secondary" on:click={closeModelDialog}>取消</button>
        <button type="button" class="primary" disabled={!modelDialog.draft.model_id.trim()} on:click={submitModelDialog}>
          {modelDialog.index === null ? "添加" : "保存"}
        </button>
      </footer>
    </div>
  </div>
{/if}

<style>
  /* ---------- 供应商卡片 ---------- */
  .provider-list { display: grid; gap: 12px; margin-top: 18px; }
  .provider-card {
    border: 1px solid var(--line);
    border-radius: var(--radius-m);
    background: var(--field);
    overflow: hidden;
    transition: border-color 0.16s var(--ease);
  }
  .provider-card:hover { border-color: var(--line-strong); }
  .provider-card.open { border-color: rgba(201, 244, 59, 0.35); }
  .provider-card.off .provider-name,
  .provider-card.off .provider-glyph { opacity: 0.45; }

  .provider-head {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 10px 12px 10px 6px;
  }
  .provider-disclose {
    display: flex;
    align-items: center;
    gap: 10px;
    flex: 1 1 auto;
    min-width: 0;
    background: transparent;
    border: 0;
    border-radius: var(--radius-s);
    padding: 8px 10px;
    color: var(--text);
    text-align: left;
  }
  .provider-disclose:hover { background: var(--panel-2); }
  .provider-glyph { width: 20px; height: 20px; flex: 0 0 auto; fill: var(--accent); opacity: 0.9; }
  .provider-name { font-weight: 600; font-size: 14px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .provider-id { font: 500 11.5px/1 var(--font-mono); color: var(--muted); white-space: nowrap; }
  .provider-meta { margin-left: auto; font-size: 12px; color: var(--muted); white-space: nowrap; }
  .provider-card.open .provider-meta { color: var(--text-2); }
  .provider-arrow { width: 18px; height: 18px; flex: 0 0 auto; fill: var(--muted); transition: transform 0.2s var(--ease); }
  .provider-card.open .provider-arrow { transform: rotate(180deg); fill: var(--accent); }

  /* 启用开关 */
  .switch { display: inline-flex; align-items: center; cursor: pointer; flex: 0 0 auto; padding: 4px; }
  .switch input { position: absolute; opacity: 0; width: 0; height: 0; }
  .switch-track {
    display: block;
    width: 34px;
    height: 20px;
    border-radius: 999px;
    background: var(--line-strong);
    position: relative;
    transition: background 0.16s var(--ease);
  }
  .switch-thumb {
    position: absolute;
    top: 2px;
    left: 2px;
    width: 16px;
    height: 16px;
    border-radius: 50%;
    background: var(--text-2);
    transition: transform 0.16s var(--ease), background 0.16s var(--ease);
  }
  .switch input:checked + .switch-track { background: var(--accent); }
  .switch input:checked + .switch-track .switch-thumb { transform: translateX(14px); background: var(--accent-ink); }
  .switch input:focus-visible + .switch-track { box-shadow: var(--ring); }
  .sr-only {
    position: absolute; width: 1px; height: 1px;
    margin: -1px; padding: 0; overflow: hidden;
    clip: rect(0 0 0 0); white-space: nowrap; border: 0;
  }

  /* 展开体 */
  .provider-body { border-top: 1px dashed var(--line); padding: 16px 16px 12px; }
  .provider-fields { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 14px 16px; }
  .provider-fields label { display: grid; gap: 6px; font-size: 12.5px; color: var(--text-2); }
  .provider-fields .key-clear { align-self: end; }
  .field-note { color: var(--muted); font-size: 11.5px; }
  .provider-advanced { grid-column: 1 / -1; display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 16px; }

  .key-input { position: relative; display: block; }
  .key-input input { width: 100%; padding-right: 40px; }
  .key-eye {
    position: absolute;
    right: 4px;
    top: 50%;
    transform: translateY(-50%);
    border: 0;
    background: transparent;
    color: var(--muted);
    width: 30px;
    height: 30px;
    display: grid;
    place-items: center;
    border-radius: 6px;
  }
  .key-eye:hover { color: var(--text); background: var(--panel-2); }
  .key-eye svg { width: 17px; height: 17px; fill: currentColor; }

  /* 模型列表 */
  .model-section { margin-top: 16px; border: 1px solid var(--line); border-radius: var(--radius-s); background: var(--panel); }
  .model-section-head {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 10px 12px;
    border-bottom: 1px solid var(--line);
  }
  .model-section-head b { font-size: 13px; }
  .model-count { font-size: 12px; color: var(--muted); }
  .model-section-actions { margin-left: auto; display: inline-flex; align-items: center; gap: 6px; }
  .add-model {
    border: 1px solid rgba(201, 244, 59, 0.55);
    background: rgba(201, 244, 59, 0.08);
    color: var(--accent);
    border-radius: var(--radius-s);
    padding: 6px 12px;
    font-size: 12.5px;
    font-weight: 600;
  }
  .add-model:hover { background: rgba(201, 244, 59, 0.16); }

  .probe-note { margin: 10px 12px 0; font-size: 12px; color: var(--ok); }
  .probe-note.bad { color: var(--danger); }

  .model-empty {
    display: flex;
    align-items: center;
    gap: 12px;
    margin: 12px;
    padding: 18px 14px;
    border: 1px dashed var(--line-strong);
    border-radius: var(--radius-s);
    color: var(--muted);
    font-size: 13px;
  }
  .model-empty svg { width: 22px; height: 22px; fill: var(--muted); flex: 0 0 auto; }

  .model-list { list-style: none; margin: 0; padding: 4px 0; }
  .model-item {
    display: flex;
    align-items: center;
    gap: 14px;
    padding: 9px 12px;
  }
  .model-item:hover { background: var(--panel-2); }
  .model-item + .model-item { border-top: 1px solid var(--line); }
  .model-id { min-width: 0; flex: 1 1 30%; display: grid; }
  .model-id .mono { font-size: 13px; color: var(--text); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .model-id em { color: var(--muted); font-style: normal; }
  .model-display { font-size: 11.5px; color: var(--muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .model-tags { display: inline-flex; gap: 6px; flex-wrap: wrap; }
  .tag {
    border: 1px solid var(--line);
    border-radius: 999px;
    padding: 3px 10px;
    font: 500 11px/1.4 var(--font-mono);
    color: var(--text-2);
    white-space: nowrap;
  }
  .tag.accent { color: var(--accent); border-color: rgba(201, 244, 59, 0.4); background: rgba(201, 244, 59, 0.07); }
  .model-actions { display: inline-flex; gap: 2px; flex: 0 0 auto; }
  .danger-text:hover { color: var(--danger); }

  .provider-foot { display: flex; justify-content: flex-end; padding: 8px 4px 2px; }

  .provider-empty {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-top: 18px;
    padding: 26px 16px;
    border: 1px dashed var(--line-strong);
    border-radius: var(--radius-m);
    color: var(--muted);
    font-size: 13.5px;
  }
  .provider-empty svg { width: 26px; height: 26px; fill: var(--muted); flex: 0 0 auto; }

  /* ---------- 绑定 ---------- */
  .binding-list { display: grid; gap: 10px; margin-top: 18px; }
  .binding-row {
    display: grid;
    grid-template-columns: 9.5rem minmax(0, 1fr) minmax(0, 1fr);
    gap: 14px;
    align-items: center;
    border: 1px solid var(--line);
    border-radius: var(--radius-s);
    background: var(--field);
    padding: 10px 14px;
  }
  .binding-row b { font-size: 13px; }
  .binding-row label { display: grid; gap: 4px; font-size: 11.5px; color: var(--muted); }

  /* ---------- 添加模型弹窗 ---------- */
  .dialog-backdrop {
    position: fixed;
    inset: 0;
    z-index: 60;
    background: rgba(5, 7, 5, 0.66);
    backdrop-filter: blur(3px);
    display: grid;
    place-items: center;
    padding: 20px;
  }
  .dialog {
    width: min(520px, 100%);
    max-height: min(86dvh, 720px);
    overflow: auto;
    background: var(--panel);
    border: 1px solid var(--line-strong);
    border-radius: var(--radius-m);
    box-shadow: 0 24px 60px rgba(0, 0, 0, 0.5);
    padding: 18px 20px 20px;
  }
  .dialog-head { display: flex; align-items: center; justify-content: space-between; margin-bottom: 10px; }
  .dialog-head h3 { margin: 0; font-size: 16px; }
  .dialog-close { font-size: 14px; }
  .dialog-smart { margin: 6px 0 4px; }
  .dialog-field { display: grid; gap: 6px; font-size: 12.5px; color: var(--text-2); margin-top: 14px; }
  .dialog-cols { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
  .tip-anchor { position: relative; display: flex; align-items: center; gap: 8px; }
  .tip-anchor input { flex: 1 1 auto; }
  .tip-mark {
    flex: 0 0 auto;
    width: 18px;
    height: 18px;
    display: grid;
    place-items: center;
    border-radius: 50%;
    border: 1px solid var(--line-strong);
    color: var(--muted);
    font: 600 11px/1 var(--font-sans);
    cursor: help;
    position: relative;
  }
  .tip-mark:hover, .tip-mark:focus-visible { color: var(--accent); border-color: rgba(201, 244, 59, 0.55); }
  .tip-mark[data-tip]:hover::after, .tip-mark[data-tip]:focus-visible::after {
    content: attr(data-tip);
    position: absolute;
    left: 50%;
    bottom: calc(100% + 8px);
    transform: translateX(-50%);
    width: 240px;
    background: var(--panel-2);
    border: 1px solid var(--line-strong);
    border-radius: var(--radius-s);
    color: var(--text-2);
    font: 400 12px/1.5 var(--font-sans);
    padding: 8px 10px;
    white-space: normal;
    z-index: 5;
    box-shadow: 0 10px 28px rgba(0, 0, 0, 0.45);
  }
  .dialog-foot { display: flex; justify-content: flex-end; gap: 10px; margin-top: 20px; }

  [data-tip] { position: relative; }
  .switch[data-tip]:hover::after {
    content: attr(data-tip);
    position: absolute;
    right: 0;
    bottom: calc(100% + 6px);
    background: var(--panel-2);
    border: 1px solid var(--line-strong);
    border-radius: var(--radius-s);
    color: var(--text-2);
    font-size: 12px;
    padding: 5px 9px;
    white-space: nowrap;
    z-index: 5;
  }

  @media (max-width: 900px) {
    .provider-fields, .provider-advanced, .dialog-cols { grid-template-columns: 1fr; }
    .binding-row { grid-template-columns: 1fr; }
    .model-item { flex-wrap: wrap; }
    .model-id { flex-basis: 100%; }
  }
</style>
