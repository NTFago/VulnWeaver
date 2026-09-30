<script lang="ts">
  import { fade, fly } from "svelte/transition";

  /** 危险操作确认弹窗：Esc / 点击遮罩取消，回车确认。 */

  export let title: string;
  export let body: string;
  export let confirmLabel = "删除";
  export let busy = false;
  export let onConfirm: () => void = () => {};
  export let onCancel: () => void = () => {};

  function handleKey(event: KeyboardEvent): void {
    if (event.key === "Escape") onCancel();
  }
</script>

<svelte:window on:keydown={handleKey} />

<div class="backdrop" transition:fade={{ duration: 120 }} on:click|self={onCancel} role="presentation">
  <div class="dialog" role="alertdialog" aria-modal="true" aria-label={title} transition:fly={{ y: 14, duration: 160 }}>
    <h3>{title}</h3>
    <p>{body}</p>
    <footer>
      <button class="secondary" disabled={busy} on:click={onCancel}>取消</button>
      <button class="danger" disabled={busy} on:click={onConfirm}>{confirmLabel}</button>
    </footer>
  </div>
</div>

<style>
  .backdrop {
    position: fixed;
    inset: 0;
    z-index: 70;
    background: rgba(5, 7, 5, 0.66);
    backdrop-filter: blur(3px);
    display: grid;
    place-items: center;
    padding: 20px;
  }
  .dialog {
    width: min(420px, 100%);
    background: var(--panel);
    border: 1px solid var(--line-strong);
    border-radius: var(--radius-m);
    box-shadow: 0 24px 60px rgba(0, 0, 0, 0.5);
    padding: 18px 20px 20px;
  }
  h3 { margin: 0 0 8px; font-size: 16px; }
  p { margin: 0; color: var(--text-2); font-size: 13.5px; line-height: 1.6; }
  footer { display: flex; justify-content: flex-end; gap: 10px; margin-top: 20px; }
</style>
