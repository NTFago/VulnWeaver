<script lang="ts">
  import { tick } from "svelte";
  import type { Job, QueueEvent } from "@vulnweaver/contracts";
  import { formatDate, shortId } from "../format";
  import { eventCategory, eventCategoryLabels, eventMatchesFilter, eventTitle, type EventCategory, type EventFilter } from "../i18n";

  /**
   * 关键事件流：按时间倒序展示任务事件，支持分类过滤与自动滚动；
   * 事件标题中文化，载荷保留原文可展开。
   */

  export let events: QueueEvent[] = [];
  export let jobs: Job[] = [];

  const filters: Array<{ key: EventFilter; label: string }> = [
    { key: "all", label: "全部" },
    { key: "stage", label: "阶段" },
    { key: "job", label: "作业" },
    { key: "finding", label: "发现" },
    { key: "error", label: "错误" },
  ];

  let activeFilter: EventFilter = "all";
  let autoScroll = true;
  let listEl: HTMLOListElement | null = null;

  $: kindById = new Map(jobs.map((job) => [job.id, job.kind] as const));
  $: visibleEvents = [...events]
    .reverse()
    .filter((event) => eventMatchesFilter(event, activeFilter));

  async function syncScroll(_eventCount: number, enabled: boolean): Promise<void> {
    await tick();
    if (enabled && listEl) listEl.scrollTop = 0;
  }
  $: void syncScroll(events.length, autoScroll);
</script>

<div class="stream-toolbar">
  <div class="filter-chips" role="group" aria-label="事件过滤">
    {#each filters as filter (filter.key)}
      <button class="chip" class:active={activeFilter === filter.key} aria-pressed={activeFilter === filter.key} on:click={() => (activeFilter = filter.key)}>{filter.label}</button>
    {/each}
  </div>
  <label class="autoscroll"><input type="checkbox" bind:checked={autoScroll} />自动滚动</label>
</div>
{#if visibleEvents.length === 0}
  <div class="compact-empty">{events.length === 0 ? "尚未接收事件。" : "当前过滤条件下没有事件。"}</div>
{:else}
  <ol class="timeline stream-list" bind:this={listEl}>
    {#each visibleEvents as event (event.event_id)}
      {@const category = eventCategory(event) as EventCategory}
      <li class="cat-{category}">
        <span class="seq">{String(event.sequence).padStart(2, "0")}</span>
        <div class="event-body">
          <b><span class={`cat-chip ${category}`}>{eventCategoryLabels[category]}</span>{eventTitle(event, kindById)}</b>
          <small>{formatDate(event.occurred_at)} · {shortId(event.event_id)}</small>
          <details><summary>载荷</summary><code>{JSON.stringify(event.payload, null, 2)}</code></details>
        </div>
      </li>
    {/each}
  </ol>
{/if}

<style>
  .stream-toolbar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 12px;
    flex-wrap: wrap;
    margin-top: 14px;
  }
  .filter-chips { display: flex; gap: 6px; flex-wrap: wrap; }
  .chip {
    border: 1px solid var(--line);
    border-radius: 999px;
    background: transparent;
    color: var(--muted);
    padding: 5px 13px;
    font-size: 12px;
    font-weight: 600;
    transition: color 0.16s var(--ease), border-color 0.16s var(--ease), background 0.16s var(--ease);
  }
  .chip:hover { color: var(--text); border-color: var(--line-strong); }
  .chip.active {
    color: var(--accent);
    border-color: rgba(201, 244, 59, 0.5);
    background: rgba(201, 244, 59, 0.07);
  }
  .autoscroll {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    font-size: 12.5px;
    color: var(--muted);
    cursor: pointer;
    white-space: nowrap;
  }
  .autoscroll input { width: 14px; height: 14px; accent-color: var(--accent); }
  .stream-list li { padding-left: 10px; border-radius: 4px; }
  .stream-list li.cat-stage { border-left: 2px solid var(--accent); }
  .stream-list li.cat-job { border-left: 2px solid var(--warn); }
  .stream-list li.cat-finding { border-left: 2px solid var(--danger); }
  .stream-list li.cat-error { border-left: 2px solid #c94a38; }
  .stream-list li.cat-system { border-left: 2px solid var(--line-strong); }
  .cat-chip {
    display: inline-flex;
    align-items: center;
    margin-right: 9px;
    padding: 1px 8px;
    border-radius: 999px;
    border: 1px solid;
    font: 600 10px/1.6 var(--font-mono);
    letter-spacing: 0.04em;
    vertical-align: 1px;
  }
  .cat-chip.stage { color: var(--accent); border-color: rgba(201, 244, 59, 0.4); }
  .cat-chip.job { color: var(--warn); border-color: rgba(227, 201, 107, 0.4); }
  .cat-chip.finding, .cat-chip.error { color: #ff9d8e; border-color: rgba(255, 115, 95, 0.4); }
  .cat-chip.system { color: var(--muted); border-color: var(--line); }
</style>
