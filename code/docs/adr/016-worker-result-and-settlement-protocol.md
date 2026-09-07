# ADR-016：Worker 最终结果与消息结算协议

- 日期：2026-09-07
- 状态：已接受
- 影响模块：Persistence、Queue、Worker SDK、后续具体 Worker

## 上下文

Worker 同时跨越 PostgreSQL 和 Redis 两个系统，二者之间不存在分布式事务。执行完成后，
数据库提交、Stream ACK 或 dead-letter 任一步发生进程崩溃或网络响应丢失，都可能导致消息
再次投递。若具体 Worker 自行处理租约、结果写入和 ACK，不同 Worker 容易产生不一致的顺序
和重复副作用。

## 决策

1. 新增不可变 `job_results` 表，以 `job_id` 为主键并保存完整 `WorkerResult` 和稳定内容指纹；
   一个 Job 只能有一个最终结果。
2. 首次写入结果必须持有对应 Job 的有效数据库租约，结果插入和 Job 终态更新位于同一事务；
   完全相同的结果允许在租约释放后幂等重放，内容冲突必须拒绝。
3. Worker 的正常顺序固定为：读取消息、取得数据库租约、启动心跳、执行、提交最终结果，
   最后 ACK。ACK 响应丢失时，后续投递直接识别已完成 Job 并 ACK，不再次执行。
4. 只有同时满足 `failure.retryable=true`、失败 kind 位于
   `retry_policy.retryable_failure_kinds` 白名单且尚未达到尝试上限时才允许重试。重试前在
   `job_attempt_failures` 按 Job + attempt 追加结构化失败记录，再释放租约并保留 pending 消息；
   最终失败或尝试耗尽先登记结构化失败结果，再写入 dead-letter Stream 并 ACK 原消息。
5. dead-letter 写入和原消息 `XACK` 通过同一 Redis Lua 脚本完成，相关键使用相同 hash tag；
   原 Stream message ID 对应有限 TTL 的内容指纹，等价重放返回同一死信 ID，冲突重放被拒绝。
6. Worker 停止后不再领取新消息；执行器收到取消事件并在宽限期内结束。宽限期耗尽时取消
   执行协程、释放仍归本 Worker 所有的租约并保留消息，供后续接管。
7. Worker SDK 只编排结构化 `Job`/`WorkerResult`，不执行任意命令、不访问 Docker Socket；
   动态执行仍只能通过独立 Sandbox Runner。
8. 心跳正常结束且与执行器在同一事件循环轮次完成时优先消费执行器结果；心跳失败按第 11 条
   处理。结果写入仍由数据库租约进行最终校验；`XAUTOCLAIM` 扫描持续使用 Redis 返回的游标，
   完整扫描后再从 `0-0` 开始。
9. fresh 消息与可接管 PEL 批次轮换优先级；一次 PEL 扫描没有得到消息时仍读取 fresh 消息，
   两者均为空时使用阻塞读取退让，避免大 PEL 令新任务饥饿或空转。
10. `WAITING_PERMISSION` 是可恢复状态，Worker 保留其 pending 消息；许可服务将 Job 恢复为
    `queued` 后由同一消息继续。成功、取消和已有结果才 ACK，最终失败才 dead-letter。
11. 心跳的瞬时数据库错误在当前执行期间重试，明确的租约冲突立即停止执行；若心跳与执行器
    同时完成，心跳租约失败优先。结算遇到租约冲突或持久化不变量竞态时重新读取 Job，并按
    最新终态 ACK/dead-letter，仍可运行或等待许可时保留 pending。
12. `WorkerResult` 中工件与证据 ID 是集合语义，结果指纹排序后计算，列表顺序变化不构成
    幂等冲突。

## 后果

- 数据库结果提交后但 ACK 或 dead-letter 响应丢失，不会导致 Job 重复执行或重复登记结果。
- 进程崩溃会暂时保留租约与 pending 消息，待两者超时后由其他 Worker 接管；正常停止则主动
  释放租约以缩短恢复时间。
- Redis 去重 TTL 到期或 Redis 数据丢失后，dead-letter 条目仍可能再次追加，但 PostgreSQL 的
  `job_results` 始终保证业务最终结果唯一。
- 后续具体 Worker 只需实现 `JobExecutor`，统一复用并发、心跳、重试、取消和结算行为。
- 每次获准重试的失败均可按 Job 和 attempt 查询，不依赖临时日志恢复执行历史。
