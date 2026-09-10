# ADR-023：Task 失败原因进入公共契约

- 日期：2026-09-10
- 状态：已接受
- 补充：ADR-020 §5（前端显示结构化失败代码与原因）
- 影响模块：M01、M03、M07、M09、M16

## 上下文

`Job` 已经有完整的失败透出链路：`jobs.failure` JSONB 列、`Job.failure` 契约字段、`JobStatusChangedPayload.failure`，以及前端对 `job.failure.message` / `job.failure.code` 的渲染。`Task` 是唯一缺少这半条链路的聚合。

编排层在**没有 Job 存在**时也会失败——`_fail_task` 正是为这种情形准备的，例如初始 Job 的策略门禁拒绝（`initial_job_policy_denied`）。此时 `OrchestrationError.failure`（含 code、kind、message、retryable、details）既没有落库，也没有进入 `task.status_changed` 事件 payload，日志行同样不含 failure code。结果是 `/api/tasks/{id}` 返回的 Task 资源里没有任何原因，前端只能显示"失败"，运维只能靠重放编排流程才能定位。

ADR-020 §5 已经把"前端显示结构化失败代码、原因与退出码"定为决策，但该决策只覆盖了 Job 失败。本 ADR 补齐缺失的一半，不引入新机制。

## 决策

1. 按 `Job` 的既有形状给 `Task` 增加失败字段：`tasks.failure` JSONB 可空列（`none_as_null=True`，与 `jobs.failure` 一致，迁移 `0019_task_failure`）、`$defs.Task.failure` 与 `$defs.TaskStatusChangedPayload.failure` 均为 **required 但可空** 的 `StructuredFailure | null`。
2. `TaskRepository.set_status` 接受 `failure` 参数并写入；非空时经 `validate_contract("StructuredFailure", …)` 校验。**两条失败路径都要带原因**：编排层的 `_fail_task`（还没有 Job 时的失败）直接落库 `error.failure`；任务聚合的 `_task_failure`（全部 Job 均失败/取消且无成功时任务判为 FAILED）取最早失败 Job 的结构化失败，并在 `details` 中附加 `job_id` / `job_kind` 以便追溯到具体执行单元。两条路径都同时写入 Task 与状态事件。
3. 其他 `task.status_changed` 生产者（任务聚合、取消、测试工厂）显式发送 `failure: null`，使"失败原因是否存在"成为契约层可判定的属性，而不是可选的旁路信息。
4. 复用 `tasks.result` 被明确否决：它是 `String(32)`，`ck_tasks_result` 只允许 `success` / `partial` / `no_findings`，且 `ck_tasks_terminal_result` 禁止 `status='failed'` 时 `result` 非空。失败与成功结果是正交的两个维度，不能挤进同一列。
5. Orchestrator 的 `orchestration_result` 日志行补 `failure_code` 与 `failure_details`，使结构化日志与契约字段表达同一事实。

## 后果

- 任务失败后，`GET /api/tasks/{id}` 与任务事件流都直接携带失败码、消息与 details（例如 `resource_limit_exceeded` 的具体资源项），前端任务页可原地展示原因，无需查容器日志或重放流程。
- 上传失败之外的用户可见失败路径不再需要"猜"。
- 公共契约新增 required 字段：所有 Task 构造点与 `task.status_changed` 生产者必须同步补 `failure`（Python 侧由 pyright 强制找齐）。这是本次改动中测试文件需要批量补充 `failure=None` 的原因。
- 保持 `schema_version` 为 `1.0.0`：新增可空字段是向后兼容的增量变更，既有消费者忽略该字段仍可工作。
