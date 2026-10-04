# 2026-10-04 分页语义审计续审

审查范围：`feat/realworld-acceptance-samples @ 9251e79` 相对 `main` 新增的分页回退审计、持久断点、证据投影和 Worker 重试链路。本轮只读审查产品代码；未部署或执行样本。Linux `dev` 容器中 `uv run --no-sync pytest -q tests/orchestrator/test_semantic_audit_paging.py` 为 **5 passed**。现有续跑测试手动再次调用 executor，未经过 Worker 结算，因此不能覆盖下列问题。

| 编号 | 优先级 | 发现与触发条件 | 修复判据 |
|---|---|---|---|
| RP-01 | P1 | `semantic_audit.py:481-483` 截止时间到达时保存断点并抛出 `FailureKind.TIMEOUT`，但 `:1358-1359` 经 `_failed`（`:1380-1393`）返回 `retryable=False`。`worker.py:375-380` 要求该位为真才重试，所以正常的 8 小时分页截止会直接使 Job 终止；断点不会被自动消费，未审计的函数保持遗漏。`default_retry_policy` 虽包含 TIMEOUT，仍不起作用。 | 截止时间失败返回可重试结构化失败，并用 Worker 结算级测试确认下一次 attempt 从断点继续；重试上限耗尽时明确报告不完整覆盖。 |
| RP-02 | P1 | `_FallbackState` 只保存 `page_count`/`total_functions`，不保存页大小或有序函数索引摘要（`semantic_audit.py:173-212`）；恢复时用当前页大小重新计算页数和切片（`:469-485`），汇总也用当前页大小计算 `audited_functions`/`complete`（`:624-630`）。例：原页大小 64、128 个函数，审完第 1 页后部署把页大小改为 128；恢复得到 `page_count=1`，不再调用模型，却将 1 个旧片段记为 128 个函数、`complete=true`。 | 断点绑定页大小和有序索引身份；恢复时校验一致，不一致则安全重审或显式失败，绝不把未审计函数计入覆盖。 |
| RP-03 | P2 | 每页 `_project` 用同一 `run_id`、CWE、位置和约束生成 `evidence_id`（`semantic_audit.py:913-921`），证据内容却包含该页不同的 `report_ref`/摘要（`:922-932`, `:1042-1085`）。模型在两页报告同一位置和约束时，第二页 `EvidenceRepository.create` 会因同 ID、不同内容抛 `EntityConflict`（`repositories.py:1505-1525`），分页审计中断；投影没有按页限制位置，也没有在证据创建处处理该冲突。 | 用页片段身份区分不可变证据，或对跨页重复候选去重并保留两个片段的可追溯关系；加入重复位置跨页回归。 |

RP-01 和 RP-02 破坏“分页覆盖所有索引函数并可恢复”的主张；修复前不能把回退审计的 `coverage.complete` 当成充分覆盖证明。
