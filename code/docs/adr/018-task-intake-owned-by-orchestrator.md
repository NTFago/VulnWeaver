# ADR-018：任务接入与初始 Job 编排职责分离

- 日期：2026-09-08
- 状态：已接受
- 影响模块：M02、M03、M04、M07、M08

## 上下文

API 接收任务时若直接创建 `VALIDATE` Job 并投递 `job.requested`，就会把分析流程、重试策略和状态迁移固化在接入层。这样既绕过 LangGraph 编排与 Policy Engine，也会让后续源码、ELF、权限中断和恢复流程在多个入口重复实现。

## 决策

1. API 只校验请求契约、项目归属和工件版本引用，并在同一 PostgreSQL 事务中创建 `CREATED` Task、序号 0 的 `task.requested` 事件及 Outbox 记录。
2. `task.requested` 是 v1 公共队列事件，负载只包含 Task ID 与已登记的工件版本 ID；不得携带任意命令、容器参数或宿主路径。
3. LangGraph 编排服务消费该事件，执行输入验证、流程选择、Policy Engine 校验和初始 Job 创建。只有编排层可以决定首个 Job 类型、重试策略与 Task 从 `CREATED` 开始的状态迁移。
4. API 取消操作只原子更新 Task、取消其现有 Job，并在确实发生状态迁移时追加一次事件；不同幂等键的并发取消也不能生成重复状态事件。

## 后果

- API 不再是隐式编排器，控制面分层和策略入口与总体架构一致。
- 在 M07 实现前，新 Task 会稳定停留在 `CREATED`，Job 列表为空；这属于明确的阶段性状态，不得由 API 临时补建 Job。
- 编排服务必须实现 `task.requested` 消费、幂等领取和首批 Job/Outbox 同事务登记，作为 M07 的契约验收项。
