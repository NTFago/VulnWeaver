<script lang="ts">
  /** 登录 / 初始改密页面。字段状态保留在本组件内，提交后由父级执行实际请求。 */

  type SubmitPayload =
    | { type: "login"; username: string; password: string }
    | { type: "register"; username: string; password: string }
    | { type: "password"; currentPassword: string; newPassword: string };

  export let mode: "auth" | "password" = "auth";
  export let registrationOpen = false;
  export let busy = false;
  export let error = "";
  export let onSubmitLogin: (username: string, password: string) => void = () => {};
  export let onSubmitRegister: (username: string, password: string) => void = () => {};
  export let onSubmitPassword: (currentPassword: string, newPassword: string) => void = () => {};

  let username = "";
  let password = "";
  let registrationPassword = "";
  let registrationConfirmation = "";
  let currentPassword = "";
  let newPassword = "";
  let confirmPassword = "";
  let localError = "";

  function submitLogin(): void {
    localError = "";
    onSubmitLogin(username, password);
  }

  function submitRegister(): void {
    if (registrationPassword !== registrationConfirmation) {
      localError = "两次输入的密码不一致";
      return;
    }
    localError = "";
    onSubmitRegister(username, registrationPassword);
  }

  function submitPassword(): void {
    if (newPassword !== confirmPassword) {
      localError = "两次输入的新密码不一致";
      return;
    }
    localError = "";
    onSubmitPassword(currentPassword, newPassword);
  }
</script>

<main class="auth-shell" class:password-shell={mode === "password"}>
  <section class="auth-intro">
    <a class="wordmark" href="/" aria-label="VulnWeaver 首页"><span>VW</span>VULNWEAVER</a>
    {#if mode === "password"}
      <div class="auth-copy"><h1>在继续之前，<br />请设置你的密码。</h1></div>
    {:else}
      <div class="auth-copy">
        <h1>让每一个漏洞结论<br />都能被追溯。</h1>
        <p>为已授权样本编排静态分析、独立复核与受控验证。模型提出观点，证据决定结论。</p>
      </div>
      <ul class="trust-line">
        <li>默认禁网</li>
        <li>原始工件不可变</li>
        <li>控制面与执行面隔离</li>
      </ul>
    {/if}
  </section>
  <section class="auth-panel">
    {#if mode === "password"}
      <form class="auth-form" on:submit|preventDefault={submitPassword}>
        <h2>更改密码</h2>
        <p class="muted">新密码至少 12 个字符，更新后当前会话保留。</p>
        {#if localError}<div class="alert error" role="alert">{localError}</div>{/if}
        {#if error}<div class="alert error" role="alert">{error}</div>{/if}
        <label>初始密码<input bind:value={currentPassword} type="password" autocomplete="current-password" required /></label>
        <label>新密码<input bind:value={newPassword} type="password" minlength="12" autocomplete="new-password" required /></label>
        <label>确认新密码<input bind:value={confirmPassword} type="password" minlength="12" autocomplete="new-password" required /></label>
        <button class="primary wide" disabled={busy}>{busy ? "正在更新…" : "保存并继续"}</button>
      </form>
    {:else}
      <form class="auth-form" on:submit|preventDefault={registrationOpen ? submitRegister : submitLogin}>
        <h2>{registrationOpen ? "创建管理员账号" : "登录"}</h2>
        <p class="muted">{registrationOpen ? "这是全新安装。创建唯一的本地管理员后即可开始使用。" : "使用你的本地管理员账号继续。"}</p>
        {#if localError}<div class="alert error" role="alert">{localError}</div>{/if}
        {#if error}<div class="alert error" role="alert">{error}</div>{/if}
        <label>账号<input bind:value={username} autocomplete="username" required /></label>
        {#if registrationOpen}
          <label>密码<input bind:value={registrationPassword} type="password" minlength="12" autocomplete="new-password" required /></label>
          <label>确认密码<input bind:value={registrationConfirmation} type="password" minlength="12" autocomplete="new-password" required /></label>
        {:else}<label>密码<input bind:value={password} type="password" autocomplete="current-password" required /></label>{/if}
        <button class="primary wide" disabled={busy}>{busy ? "正在处理…" : registrationOpen ? "创建账号并进入" : "进入工作台"}</button>
        <p class="fine-print">仅用于明确授权的本地样本与开源项目。</p>
      </form>
    {/if}
  </section>
</main>
