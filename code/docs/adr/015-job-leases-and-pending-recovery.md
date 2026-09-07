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
2. 领取先用无锁读取处理终态、许可等待、有效租约和退避等只读结果；只有可能改变状态时才在
   Job 行锁内复查并更新。Job 与 PostgreSQL 服务器时间由同一次查询返回。
3. 每次首次领取或过期接管都会生成唯一 fencing token 并增加 `attempt`；续租、释放、失败审计
   和最终结果写入必须同时匹配 owner 与 token，旧执行者恢复后不能覆盖新租约结果。token 作为
   `Lease` 的可选字段加入 v1，保持历史消息可读取；缺少 token 的旧租约不能续约或结算，只能在
   到期后安全接管。
4. 同一 owner 对有效租约重复领取返回 `already_owned`，不续租、不增加 attempt，也不授予第二次
   执行权。优雅停止在确认执行协程已结束后释放租约并退还本次 attempt；崩溃或过期接管仍消耗
   attempt。
5. 达到 `retry_policy.max_attempts` 后，领取者先取得不增加 attempt 的专用结算租约，再返回
   `exhausted`；只有该租约的 owner 与 fencing token 可以登记最终失败和 dead-letter。
6. 可重试失败写入 `job_attempt_failures` 时同步保存数据库 `retry_not_before`，领取者在该时间前
   只能得到 `backing_off`，从而跨 Worker 执行 `retry_policy.backoff_seconds`。
7. Redis pending 接管使用 `XAUTOCLAIM`，并保留原 Stream message ID 与事件内容；接管后仍必须
   取得数据库租约才能执行。
8. 可重试失败通过释放租约把 Job 返回 `queued`，消息在成功持久化最终结果前不得 ACK。

## 后果

- Worker 崩溃后，其他消费者必须同时满足消息 idle 超时和数据库租约过期才能接管执行。
- ACK 丢失造成的重复投递不会绕过数据库租约和尝试次数。
- Redis PEL idle 到期可以转移消息，但有效数据库租约的同 owner 重领和其他 owner 竞争都不会
  启动第二个执行器。
- 幂等最终结果、心跳循环和 dead-letter 原子处理采用 ADR-016 定义的完成协议。
