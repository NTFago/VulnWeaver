# ADR-015：PostgreSQL Job 租约与 Redis Pending 接管分离

- 日期：2026-09-07
- 状态：已接受
- 影响模块：Persistence、Queue、后续 Worker SDK

## 上下文

Redis Streams 消费者组可以发现和转移未 ACK 的 pending 消息，但 Redis 不是系统事实来源，
仅凭消费者所有权不能保证同一 Job 只有一个有效执行者。Worker 崩溃、ACK 丢失和重复消息
都可能使多个进程观察到同一个 Job。

## 决策

1. PostgreSQL `jobs.lease` 是执行所有权的事实来源；Redis pending 所有权只负责消息传输。
2. 租约领取在 Job 行锁内完成，时间使用 PostgreSQL 服务器时间；有效租约只能由原 owner 续约或释放。
3. 首次领取和过期接管都会增加 `attempt`；同一 owner 对有效租约重复领取是幂等操作，不增加次数。
4. 达到 `retry_policy.max_attempts` 后返回明确的 `exhausted` 结果，由后续 Worker 完成失败结果登记和 dead-letter。
5. Redis pending 接管使用 `XAUTOCLAIM`，并保留原 Stream message ID 与事件内容；接管后仍必须取得数据库租约才能执行。
6. 优雅停止或可重试失败通过释放租约把 Job 返回 `queued`，消息在成功持久化最终结果前不得 ACK。

## 后果

- Worker 崩溃后，其他消费者必须同时满足消息 idle 超时和数据库租约过期才能接管执行。
- ACK 丢失造成的重复投递不会绕过数据库租约和尝试次数。
- 幂等最终结果、心跳循环和 dead-letter 原子处理采用 ADR-016 定义的完成协议。
