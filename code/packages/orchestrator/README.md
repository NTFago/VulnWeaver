# VulnWeaver 编排层

本包负责消费 `task.requested` 的 LangGraph 控制面流程：校验输入归属、选择源码或二进制导入管线、通过 Policy Engine 校验初始 ActionPlan，并在 PostgreSQL 同一事务中登记首个 Job 与 Outbox。

每个已完成节点追加独立检查点。`PostgresCheckpointStore` 使用 PostgreSQL advisory transaction lock 分配任务内序号。重放从最新检查点之后继续；Job 提交后、检查点提交前发生崩溃时，确定性 Job/Outbox 标识保证结果幂等。

消费者交替处理新事件与过期 pending。永久校验/策略失败落库后 ACK；瞬时异常保留 pending 供接管。待许可 Job 保存为 `waiting_permission`，不产生可供 Worker 执行的 Outbox。

## 独立复核

`IndependentModelReviewer(database, gateway, store).review(finding_id, attempt_key=...)` 是显式调用的复核应用服务，尚未接入常驻消费者。调用方注入已配置 `ModelTier.REVIEW` 的模型网关和服务自有工件库。

- 复用 v1 `Review` Schema，只接受模型的 outcome/rationale；Finding/Review 身份、模型来源、时间与历史关联由服务确定。
- 输入来自 `ReviewFactContext`，排除静态审计自由推理、模型解释及历史复核结论。当前仅提供可验证事实元数据，不读取引用工件全文；证据不足必须保留不可验证/争议状态，不能假称已阅读源码。
- 模型网络调用与工件写入不持有数据库行锁。落库时重新锁定 Finding、比较事实与复核历史，并锁定 Task 校验取消/终态，过期结论只保留审计，不改变 Finding。
- 确认必须经过已有领域门禁；缺少强可复现证据时保存 `unverifiable`，原始确认建议留在不可变结论工件中。复核结论自身只有 contextual 强度、零权重，不作为下一轮确认依据。
- AgentRun、Review、Evidence 及关联在同一事务提交。结论工件内保存事实快照、提议和 run ID；Evidence 保存输入证据 ID、摘要与来源。工件先发布而数据库事务失败时保留未引用对象，不删除未知工件。
- 相同 Finding 与 `attempt_key` 从 PostgreSQL 回放，不重复登记或再次调用模型；失败也保留。需要新的复核尝试时使用新 key，并由上层控制重试预算。并发调用可能重复消耗模型 token，但只有一个事务结果生效；正式自动调度必须通过既有 Job 租约收敛调用，不将本服务当作队列执行锁。
- 模型超时/非法输出、工件失败与状态拒绝保留结构化原因。数据库异常向调用方传播，事务回滚后可使用同一 key 重试。

## 验证

在 `code/` 执行定向测试：

```text
uv run --no-sync pytest tests/contracts tests/domain tests/evidence tests/finding tests/model_gateway tests/orchestrator tests/persistence/test_repositories.py -q
pnpm exec pyright
uv run --no-sync ruff check .
```

Windows 宿主运行 psycopg 异步测试时需在 pytest 启动前设置 `asyncio.WindowsSelectorEventLoopPolicy()`；Linux/Dev Container 不需要此设置。集成测试使用独立临时数据库和模拟模型，不运行不可信样本，也不调用付费模型。

后续工作：按静态 Job 完成事件调度复核、增加有界且校验摘要的代码事实读取、Task 聚合、人工 Annotation、工作台查询。当前不能视为 T15 或 P2 整体验收完成。
