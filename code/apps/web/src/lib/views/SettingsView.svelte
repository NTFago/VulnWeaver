<script context="module" lang="ts">
  import type { ProductSettings } from "../api";

  export interface SettingsSavePayload {
    settings: ProductSettings;
    reviewApiKey: string;
    clearReviewApiKey: boolean;
    tierApiKeys: Record<string, string>;
    clearTierApiKeys: string[];
  }
</script>

<script lang="ts">
  /** 产品设置页：模型接入、工具镜像与沙箱预算。表单字段状态在本组件维护。 */

  type TierName = "planning" | "audit" | "review" | "report";

  export let productSettings: ProductSettings;
  export let busy = false;
  export let onSave: (payload: SettingsSavePayload) => Promise<boolean> = async () => false;
  export let onUpdatePassword: (currentPassword: string, newPassword: string) => Promise<boolean> = async () => false;

  const tierNames: TierName[] = ["planning", "audit", "review", "report"];
  const tierLabels: Record<TierName, string> = {
    planning: "规划 PLANNING",
    audit: "语义审计 AUDIT",
    review: "独立复核 REVIEW",
    report: "报告 REPORT",
  };

  let reviewApiKey = "";
  let clearReviewApiKey = false;
  let tierApiKeys: Record<TierName, string> = { planning: "", audit: "", review: "", report: "" };
  let clearTierApiKeys: TierName[] = [];
  let expandedTier: TierName | null = null;
  let showAdvancedSettings = false;

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
    const saved = await onSave({
      settings: productSettings,
      reviewApiKey: reviewApiKey,
      clearReviewApiKey: clearReviewApiKey,
      tierApiKeys: suppliedKeys,
      clearTierApiKeys: [...clearTierApiKeys],
    });
    if (saved) {
      reviewApiKey = "";
      clearReviewApiKey = false;
      tierApiKeys = { planning: "", audit: "", review: "", report: "" };
      clearTierApiKeys = [];
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
    <p>模型接入与执行预算保存在 PostgreSQL，Worker 在下一次任务时自动生效。数据库、Cookie 安全策略、内部服务地址和 API 密钥仍由部署方安全注入。</p>
  </div>
</section>
<div class="settings-layout">
  <nav class="settings-rail" aria-label="设置分区">
    <a href="#sec-review-model">复核模型</a>
    <a href="#sec-model-tiers">分档位模型</a>
    <a href="#sec-tool-images">工具镜像</a>
    <a href="#sec-sandbox-budgets">沙箱预算</a>
    <a href="#sec-account">账户安全</a>
  </nav>
  <div class="settings-body">
    <form class="settings-form" on:submit|preventDefault={save}>
      <section class="panel" id="sec-review-model">
        <header class="panel-head">
          <div><h2>独立复核模型</h2><p>所有模型调用在档位未单独配置时回退到这里。</p></div>
          <span class={`badge ${productSettings.api_key_configured ? "ok" : "warn"}`}>{productSettings.api_key_configured ? "API Key 已配置" : "API Key 未配置"}</span>
        </header>
        <div class="field-grid">
          <label>OpenAI 兼容端点<input bind:value={productSettings.review_model_base_url} placeholder="https://example.com/v1" /></label>
          <label>模型名称<input bind:value={productSettings.review_model_name} placeholder="review-model" /></label>
          <label>API Key<input bind:value={reviewApiKey} type="password" autocomplete="new-password" placeholder={productSettings.api_key_configured ? "留空以保留现有值" : "输入 API Key"} /></label>
        </div>
        {#if productSettings.api_key_configured}<label class="check"><input type="checkbox" bind:checked={clearReviewApiKey} /><span><b>清除已保存的 API Key</b><small>保存后立即删除；输入新值会在未勾选时替换旧值。</small></span></label>{/if}
        <div class="field-grid cols-4">
          <label>超时（秒）<input bind:value={productSettings.review_model_timeout_seconds} type="number" min="1" max="600" /></label>
          <label>最大尝试次数<input bind:value={productSettings.review_model_max_attempts} type="number" min="1" max="10" /></label>
          <label>结构修复次数<input bind:value={productSettings.review_model_repair_attempts} type="number" min="0" max="5" /></label>
          <label>请求最小间隔（秒）<input bind:value={productSettings.review_model_min_interval_seconds} type="number" min="0" max="3600" step="0.1" /></label>
        </div>
      </section>

      <section class="panel" id="sec-model-tiers">
        <header class="panel-head">
          <div><h2>分档位模型</h2><p>规划、语义审计、独立复核与报告可以接入不同模型；未配置的档位回退到独立复核模型。</p></div>
        </header>
        <div class="tier-list">
          {#each tierNames as tier (tier)}
            <div class="tier-group" class:open={expandedTier === tier}>
              <button type="button" class="tier-toggle" aria-expanded={expandedTier === tier} on:click={() => (expandedTier = expandedTier === tier ? null : tier)}>
                <b>{tierLabels[tier]}</b>
                <span class="tier-state" class:enabled={productSettings.tier_api_keys_configured?.[tier] || productSettings.model_tiers[tier].model_name}>
                  {productSettings.model_tiers[tier].model_name ? `${productSettings.model_tiers[tier].protocol} / ${productSettings.model_tiers[tier].model_name}` : "未配置，回退到复核模型"}
                </span>
                <span class="arrow" aria-hidden="true">▾</span>
              </button>
              {#if expandedTier === tier}
                <div class="tier-body">
                  <div class="field-grid">
                    <label>协议<select bind:value={productSettings.model_tiers[tier].protocol}><option value="openai">OpenAI 兼容（/chat/completions）</option><option value="anthropic">Anthropic（/v1/messages）</option></select></label>
                    <label>端点<input bind:value={productSettings.model_tiers[tier].base_url} placeholder="https://example.com/v1" /></label>
                    <label>模型名称<input bind:value={productSettings.model_tiers[tier].model_name} placeholder={`${tier}-model`} /></label>
                    <label>API Key<input bind:value={tierApiKeys[tier]} type="password" autocomplete="new-password" placeholder={productSettings.tier_api_keys_configured?.[tier] ? "留空以保留现有值" : "输入 API Key（可留空继承全局）"} /></label>
                  </div>
                  {#if productSettings.tier_api_keys_configured?.[tier]}<label class="check"><input type="checkbox" checked={clearTierApiKeys.includes(tier)} on:change={(e) => toggleTierKey(tier, e.currentTarget.checked)} /><span><b>清除该档位已保存的 API Key</b></span></label>{/if}
                  <div class="field-grid cols-4">
                    <label>上下文窗口（token，0=不限）<input bind:value={productSettings.model_tiers[tier].context_window_tokens} type="number" min="0" /></label>
                    <label>思考模式<select bind:value={productSettings.model_tiers[tier].thinking_mode}><option value="off">关闭</option><option value="default">开启（供应商默认预算）</option><option value="custom">自定义预算</option></select></label>
                    {#if productSettings.model_tiers[tier].thinking_mode === "custom"}<label>思考预算（token，≥1024）<input bind:value={productSettings.model_tiers[tier].thinking_budget_tokens} type="number" min="1024" /></label>{/if}
                    <label>超时（秒，0=沿用全局）<input bind:value={productSettings.model_tiers[tier].timeout_seconds} type="number" min="0" max="600" /></label>
                    <label>最大尝试（0=沿用全局）<input bind:value={productSettings.model_tiers[tier].max_attempts} type="number" min="0" max="8" /></label>
                  </div>
                </div>
              {/if}
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
          <span class:enabled={!!productSettings.review_model_name}><i></i>模型分析</span>
        </div>
      </section>

      <div class="advanced-anchor" id="sec-sandbox-budgets">
        <button type="button" class="secondary adv-toggle" aria-expanded={showAdvancedSettings} on:click={() => showAdvancedSettings = !showAdvancedSettings}>{showAdvancedSettings ? "收起高级设置" : "高级设置：沙箱资源与预算"}</button>
        {#if showAdvancedSettings}
          <section class="panel advanced-settings">
            <p class="muted">0 表示未设置，沿用环境变量或代码默认值；更改在下一次任务执行时生效。</p>
            {#each [["afl", "AFL++/CASR（模糊测试）"], ["proof", "Proof 工具"], ["binary", "二进制工具"]] as [tool, label]}
              <div class="field-grid cols-4 budget-block">
                <label>{label} CPU（毫秒核）<input bind:value={productSettings.sandbox_budgets[tool as "afl" | "proof" | "binary"].cpu_millis} type="number" min="0" /></label>
                <label>{label} 内存（字节）<input bind:value={productSettings.sandbox_budgets[tool as "afl" | "proof" | "binary"].memory_bytes} type="number" min="0" /></label>
                <label>{label} 磁盘（字节）<input bind:value={productSettings.sandbox_budgets[tool as "afl" | "proof" | "binary"].disk_bytes} type="number" min="0" /></label>
                <label>{label} 超时（秒）<input bind:value={productSettings.sandbox_budgets[tool as "afl" | "proof" | "binary"].timeout_seconds} type="number" min="0" max="86400" /></label>
              </div>
            {/each}
            <div class="field-grid cols-4">
              <label>Fuzz 最大执行次数<input bind:value={productSettings.fuzz_budgets.max_executions} type="number" min="0" /></label>
              <label>Fuzz 最长时长（秒）<input bind:value={productSettings.fuzz_budgets.max_duration_seconds} type="number" min="0" max="86400" /></label>
              <label>Fuzz 崩溃上限<input bind:value={productSettings.fuzz_budgets.max_crashes} type="number" min="0" max="10000" /></label>
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
