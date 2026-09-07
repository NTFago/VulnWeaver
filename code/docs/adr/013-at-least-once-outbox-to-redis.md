# ADR-013：Outbox 到 Redis Streams 的至少一次投递

- 日期：2026-09-07
- 状态：已接受
- 影响模块：M04、M08 及全部 Worker

## 上下文

PostgreSQL 是 Job 与 Outbox 的事实来源，Redis Streams 只承担队列和实时事件。两者之间没有分布式事务：进程可能在 Redis 接受消息后、PostgreSQL 提交发布状态前崩溃，因此不能宣称端到端恰好一次。

## 决策

- Dispatcher 对每条事件开启独立数据库事务，以 `FOR UPDATE SKIP LOCKED` 领取一行并在该事务内完成发布结果登记；多个实例不会同时处理同一行，慢 Redis 调用也不会让一个实例长时间锁住整个批次。
- Redis 发布成功后再标记 `published_at`；Redis 故障使用数据库服务器时间记录结构化错误与有上限的指数退避，非重试冲突进入 Outbox dead-letter 状态。
- 可恢复的传输故障不设置尝试次数上限，而是在最大退避间隔下持续重试；Outbox 是事实事件的可靠出口，因临时基础设施故障自动转死信会造成静默漏投。Worker 的业务执行重试上限与死信流由 T06 独立负责。
- 每个事件携带契约版本和稳定 `event_id`。Redis 7 使用固定 Lua 脚本原子维护短期去重记录与 `XADD`，相同 ID/相同内容返回原 Stream ID，相同 ID/不同内容被拒绝。
- 去重记录具有有限 TTL，且 Redis 数据可能丢失，因此整体交付语义仍为至少一次；T06 Worker 必须按 Job 幂等键和已有成功结果保护持久化副作用，处理成功后才 `XACK`。
- Stream 不默认自动裁剪，避免尚未消费的 Job 因长度阈值被删除；部署方只有在定义留存与恢复策略后才可配置上限。

## 后果

- Dispatcher 崩溃、数据库提交失败或网络响应丢失后，可从 PostgreSQL 重放事件而不创建新 Job。
- Redis 在去重 TTL 内不会为等价重试增加第二条 Stream entry；TTL 外或 Redis 恢复后的重复消息仍由消费者幂等处理。
- `job.requested` 与状态事件使用不同 Stream，消费者组可以独立扩缩容；租约、接管、死信消费和优雅停止由 T06 完成。
- 单条事务降低锁范围但仍在 Redis 调用期间占用一个数据库连接；若未来吞吐量要求显著提高，应增加带过期时间和所有者令牌的 Outbox 领取租约，再把网络 IO 安全移出事务。
