# ADR-019：任务编排检查点与初始 Job 结算

- 日期：2026-09-08
- 状态：已接受
- 影响模块：M04、M05、M07、M08

## 上下文

`task.requested` 通过 PostgreSQL Outbox 至少一次投递到 Redis。编排服务可能在输入校验、管线选择、策略判定、Job 提交或消息 ACK 的任一步骤崩溃。若只依赖进程内 LangGraph 状态，重启后无法确认哪些节点已经完成；若先 ACK 再创建 Job，则可能永久丢失任务；若重复创建 Job，则可能绕过幂等和策略边界。

## 决策

1. 编排主流程使用 LangGraph 显式节点：输入校验、管线选择、初始策略判定和初始 Job 持久化。
2. 每个成功节点将完整 JSON 状态追加到 PostgreSQL `orchestration_checkpoints`。同一 Task 的序号通过事务级 advisory lock 分配，检查点不可覆盖。
3. 恢复时从最新检查点之后的节点继续。若 Job 已提交但检查点尚未提交，确定性的 Job ID、幂等键和 Outbox 事件 ID 保证重放得到已有结果而不重复登记。
4. `task.requested` 只有在成功调度、等待许可或确定性失败已经落库后才 ACK。未知瞬时失败保留在 Pending Entries List，并通过 `XAUTOCLAIM` 接管；fresh 与 pending 批次交替优先级。
5. 初始 ActionPlan 必须引用部署侧加载的精确版本 ToolSpec，并通过 Policy Engine。模型输出不能提供 ToolSpec、镜像摘要或宿主执行参数。
6. 策略要求许可时只创建 `waiting_permission` Job，不写 `job.requested` Outbox。`FULL_ACCESS` 仍不绕过工具白名单、文件系统、网络和资源策略。
7. AgentRun 与检查点作为 PostgreSQL 事实新增迁移。AgentRun 写入按 ID 幂等，保存提示哈希、输入和结果引用、模型、token、耗时、决策及结构化失败。
8. 可运行编排服务只从受信任的 `TOOL_SPEC_DIRECTORY` 加载配置，不为尚未交付的 Worker 虚构镜像摘要；具体 ToolSpec 与 Compose 启用由 T12/T16 随对应镜像交付。

## 后果

- 编排进程、Redis ACK 或数据库连接中断后可以安全恢复，不会跳过策略检查或重复创建初始 Job。
- 工作台在具体分析 Worker 完成前即可看到真实的 `VALIDATING` Task 和首个 Job。
- T12/T16 必须提供与实际镜像摘要一致的 ToolSpec，之后才能在 Compose 中启用 orchestrator 服务。
- 后续节点沿用相同检查点和幂等模式扩展源码、二进制、复核、验证及报告流程。
