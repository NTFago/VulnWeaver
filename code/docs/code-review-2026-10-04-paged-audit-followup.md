# 2026-10-04 分页语义审计修复复审

复审范围：`69cfba2` 对 RP-01～03 的修复及相邻的模型失败、Worker 续跑链路。三项原问题的主要代码路径已修正：截止失败现为可重试、断点绑定页大小与有序函数 ID、跨页证据按页区分。Linux `dev` 容器使用当前源码运行 `uv run --no-sync pytest -q tests/orchestrator/test_semantic_audit_paging.py tests/worker/test_worker_semantic_audit_retry.py`，**8 passed**。本轮未运行全量门禁或部署。

> 修复记录（2026-10-04，`1ca1d20`）：两项均已修复。RF-01：`_AuditError` 原样携带网关失败的结构化 `kind`/`retryable`/`message` 到 WorkerResult；新增 Worker 结算级回归 `test_transport_failure_on_second_page_is_retried_and_resumes`（第 0 页成功、第 1 页 `model_transport_error`/DEPENDENCY/retryable 失败、Worker 自动重入队、attempt 2 从断点恢复只重跑第 1 页）。RF-02：时钟改为第 3 次调用（第 0 页完成后的截止检查）触发，测试断言 attempt 1 保存 `next_page=1`、attempt 2 仅执行剩余页（`test_deadline_after_page_zero_is_retried_and_resumes_remaining_page`）。全量门禁 761 passed / 7 skipped；部署后真实 Runner 验收 6 passed。

## 仍需修复（已全部修复，保留原始发现）

| 编号 | 优先级 | 代码证据与影响 | 修复判据 |
|---|---|---|---|
| RF-01 | P1 | 分页模型调用返回 `response.failure` 时，`semantic_audit.py:539-546` 保留失败记录后抛出新的 `_AuditError(..., FailureKind.DEPENDENCY)`，没有传递原失败的 `retryable`。`_AuditError` 默认 `retryable=False`（`:1415-1423`），Worker 于是把 Job 终结。模型网关把超时、传输异常和 HTTP 408/429/5xx 转成可重试的 `ModelTransportError`，并通过 `ModelCallResult.failure` 返回（`model-gateway/gateway.py:526-545`）。若这些故障发生在后续页，已保存的断点不会被下一次 attempt 消费，剩余函数仍未审计；`default_retry_policy` 列有 DEPENDENCY 也无效。这个问题原已存在，但 RP-01 只修正了本地 deadline 分支。 | 将网关失败的结构化 `kind`/`retryable` 保留到 WorkerResult；加入“第一页已完成、第二页模型传输失败、Worker 自动从第二页恢复”的结算级回归。 |
| RF-02 | P2 | 新增的 `test_worker_semantic_audit_retry.py:31-40` 在模拟时钟第 **2** 次调用时返回 100。`_single_shot_audit` 第 1 次调用建立开始时间（`semantic_audit.py:508`），第 2 次调用就是**第一页之前**的截止检查（`:512`）。因此首个 attempt 审计 0 页、保存 `next_page=0`，第二次 attempt 从页 0 完整重跑；测试只断言总页面集合和 attempt=2（`:74-83`），即使断点续页失效也能通过。 | 改为在第二页前触发截止，并断言第一次 attempt 保存 `next_page=1`，第二次 attempt 只执行剩余页。 |

RF-01 修复前，不应把“分页回退审计可恢复”扩展解释为模型传输故障也可恢复。RF-02 是测试覆盖缺口，不代表 RP-01 的可重试字段修复无效。
