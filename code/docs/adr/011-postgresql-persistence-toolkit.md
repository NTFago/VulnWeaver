# ADR-011：PostgreSQL 持久化工具链

- 日期：2026-09-07
- 状态：已接受
- 影响模块：M02、M03、M04、M08 及后续 PostgreSQL 消费者

## 上下文

控制面需要异步访问 PostgreSQL，并以可审查迁移维护 Schema。Job 写入必须保证 Job 与
Outbox 同事务提交，仓储也必须清晰暴露幂等冲突而不是依赖 ORM 隐式状态。

## 决策

- 使用 SQLAlchemy Core 2.x 定义表和异步事务边界，不使用跨请求共享 Session 或 ORM 隐式关系加载。
- 使用 psycopg 3 的同步/异步双接口：运行时由 `create_async_engine` 使用异步接口，Alembic 迁移使用同步接口。
- 使用 Alembic 维护不可变增量迁移；迁移文件显式声明 DDL，不从当前 metadata 动态创建历史版本。
- 状态枚举以 `VARCHAR + CHECK` 保存，契约扩展通过显式迁移完成；资源预算、失败详情和事件负载使用 JSONB。
- 每个服务操作显式创建 transaction-scoped repositories；Job 与 Outbox 只能通过同一仓储方法登记。

## 后果

- FastAPI、编排和 Dispatcher 可共享同一异步数据库基础设施，但不得跨并发任务复用连接或事务对象。
- PostgreSQL 是 Job 与待投递事件的事实来源；Redis 投递失败时可从未发布 Outbox 重放。
- 新增表或约束必须同时更新 SQLAlchemy metadata、Alembic revision 和迁移一致性测试。
- SQLAlchemy、Alembic 与 psycopg 成为持久化包的受锁文件约束依赖。
