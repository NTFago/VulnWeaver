# Agent 动态交接台账

> 本文件只维护当前进度、问题、阻碍、决策摘要、验证结果和下一步。稳定开发规则见 `AGENTS.md`；架构依据为 `系统架构设计与技术选型.md`，实现任务依据为 `系统实现模块拆分.md`。开始工作前必须阅读 `AGENTS.md` 和本文件，结束或交接前必须更新本文件。

## 1. 项目目标

构建一个面向已授权源码仓库和 x86/x64 ELF/PE 二进制的软件漏洞挖掘系统。系统通过智能体编排静态分析、逆向分析、模糊测试、独立复核、最小复现和可选利用验证，并输出可追溯的 Finding、证据链与报告。

## 2. 当前工程状态

- **项目名称**：VulnWeaver（漏洞织鉴）
- **当前阶段**：P1 控制面最小闭环（T06 Worker 租约与幂等框架已完成）
- **总体状态**：可靠 Worker SDK 已完成，可开始 T07 FastAPI 基础接口
- **最后更新**：2026-09-07
- **代码目录**：`code/` 已初始化 Python/TypeScript 工作区、Dev Container 与 Compose 基础设施
- **版本管理**：Git；CI 分支及已合并历史分支已在本地和远程清理；当前开发分支 `feat/t06-worker-reliability`，基于最新 `main`
- **稳定开发规则**：根目录 `AGENTS.md` 已建立
- **当前负责人**：Codex

## 3. 开发进度

| 模块/任务包 | 状态 | 负责人 | 完成内容 | 剩余工作 | 最后更新 |
|---|---|---|---|---|---|
| 架构设计 | 已完成 | 用户/设计阶段 | 系统目标、架构、安全、数据与技术选型已定义 | 实现中持续校验 | 2026-09-07 |
| 实现模块拆分 | 已完成 | Agent | M01-M17、P0-P5、T01-T22 已拆分 | 随实现维护依赖变化 | 2026-09-07 |
| T01 工程工作区 | 已完成 | Codex | 命名为 VulnWeaver；初始化 uv、pnpm、质量工具、Dev Container、PostgreSQL/Redis Compose；配置国内依赖源 | 无 | 2026-09-07 |
| T02 公共契约 | 已完成 | Codex | 冻结 v1.0.0 JSON Schema；生成 Python/TypeScript 类型；实现状态迁移、Task 聚合、Finding 确认、利用门禁和幂等规则；补齐运行时校验与 39 个测试 | 无 | 2026-09-07 |
| T03 PostgreSQL 迁移与仓储 | 已完成 | Codex | 主体实现及 Review 修正完成；Project、Artifact、Task（含可选 result）和 Job 枚举字段统一通过 `str()` 序列化，仓储同时接受 StrEnum 与 Schema 合法字符串，真实 PostgreSQL 回归验证写入后按枚举读回 | 无；Finding/Evidence、PAIR、运行记录和检查点由其后续任务包按职责追加迁移 | 2026-09-07 |
| T04 本地内容寻址工件库 | 已完成 | Codex | 主体实现及 Review 修正完成：字符串 `derived` 输入无法绕过谱系约束，合法字符串枚举可持久化；重复旧摘要不回退 current version；新摘要目录逐级 fsync；首版本循环外键的事务内临时 NULL 语义已明确 | 无；受控未引用对象 GC 与 MinIO 后端按后续部署需求实现 | 2026-09-07 |
| T05 Redis Streams 与 Outbox Dispatcher | 已完成 | Codex | 主体实现及 Review 修正完成：Dispatcher 改为单条事件独立事务、退避改用数据库时钟；Stream 冗余字段与载荷一致性校验、结构化读取参数错误及双 Dispatcher 真实并发测试已补齐 | 无 | 2026-09-07 |
| T01.1 CI 质量门禁 | 已完成 | Codex | Ruff/Pyright/pytest/TypeScript 分层门禁固化为 GitHub Actions 必过检查；Pyright strict 6 处类型问题已修正；`pnpm run check` 本地等价验证通过 | 无；GitHub 仓库需将 `Python quality gate` 设为 `main` 必需检查（平台配置） | 2026-09-07 |
| T06 Worker 租约与幂等框架 | 已完成 | Codex | 实现数据库权威租约、心跳续约、Redis pending 接管、并发消费、重试/尝试耗尽、不可变幂等 JobResult、结果提交后 ACK、原子 dead-letter 与优雅停止；真实 PostgreSQL/Redis 故障注入通过 | 无；具体分析执行器由 T12/T16/T19/T20 接入 Worker SDK | 2026-09-07 |

状态只允许使用：`未开始`、`进行中`、`受阻`、`待验证`、`已完成`、`已取消`。

## 4. 当前问题

| ID | 问题 | 影响 | 临时处理 | 状态 | 负责人 |
|---|---|---|---|---|---|
| Q-002 | 首版开发环境是否必须同时支持 Windows Worker 未明确 | 影响 P4 的本机验收范围 | 先冻结跨平台消息协议，Windows 执行节点在 Linux MVP 后实现 | 待处理 | 未分配 |
| Q-003 | Windows Python 3.12 在含中文的工作区路径中以 GBK 读取 uv editable `.pth`，会导致启动失败 | 影响 Windows 宿主直接使用默认 editable workspace；Dev Container/Linux 不受影响 | Windows 本机使用 `uv sync --no-editable`，验证命令使用 `uv run --no-sync`；等待 Python/uv 上游兼容或迁移到纯 ASCII 路径 | 待处理 | 未分配 |

## 5. 当前阻碍点

当前无阻碍。问题只有在导致已认领任务无法继续时才移入本节。

| ID | 阻碍描述 | 阻碍任务 | 已尝试方案 | 解除条件 | 状态 |
|---|---|---|---|---|---|
| - | 无 | - | - | - | - |

## 6. 待确认事项

| ID | 待确认决策 | 可选方案 | 默认建议 | 最晚确认阶段 | 状态 |
|---|---|---|---|---|---|
| D-001 | Python 依赖与工作区工具 | uv / Poetry / pip-tools | 已采用 uv workspace | T01 | 已确认（ADR-008） |
| D-002 | 前端包管理器 | pnpm / npm | 已采用 pnpm workspace | T01 | 已确认（ADR-008） |
| D-003 | 首版对象存储 | 本地内容寻址目录 / MinIO | 本地目录，保留 MinIO 接口 | T03 | 已由架构默认 |
| D-004 | 首版身份认证 | 暂不实现 / 本地单用户 / 完整认证 | 演示环境本地单用户，预留身份上下文 | P1 | 待确认 |

## 7. 已确认技术决策（ADR 摘要）

| ADR | 决策 | 理由 | 来源 |
|---|---|---|---|
| ADR-001 | 后端使用 Python，API 使用 FastAPI | 与 LangGraph、angr、pwntools、Ghidra 自动化生态一致 | 架构文档 |
| ADR-002 | 前端使用 Svelte 5 + TypeScript + Vite | 满足任务管理与逆向工作台需求 | 架构文档 |
| ADR-003 | PostgreSQL + Redis Streams + Outbox | 数据库保存事实，Redis 可靠投递与实时事件 | 架构文档 |
| ADR-004 | PAIR 使用 PostgreSQL 关系表和原始输出存档 | 避免首版引入独立图数据库 | 架构文档 |
| ADR-005 | 模型访问层使用 OpenAI 兼容协议 | 支持远程与本地模型切换 | 架构文档 |
| ADR-006 | 动态执行由独立 Sandbox Runner 负责 | 隔离容器运行时权限和不可信程序 | 架构文档 |
| ADR-007 | 项目命名为 VulnWeaver（漏洞织鉴），机器标识统一使用 `vulnweaver` | 名称体现证据链编织与漏洞分析定位，并统一包、镜像和 Compose 标识 | `code/docs/adr/007-project-name-and-identifiers.md` |
| ADR-008 | Python 使用 uv，TypeScript 使用 pnpm；依赖安装默认使用国内源 | 获得可复现锁文件、工作区能力并改善国内网络下的安装稳定性 | `code/docs/adr/008-workspace-tooling.md` |
| ADR-009 | 使用不挂载 Docker Socket 的 Dev Container，动态样本另交 Sandbox Runner | 统一开发工具链，同时保持开发环境与不可信执行边界 | `code/docs/adr/009-containerized-development.md` |
| ADR-010 | 使用根目录 Git 仓库进行版本管理，`main` 为集成基线 | 为多人和多 Agent 开发提供可审查、可追溯的版本历史 | `code/docs/adr/010-git-version-control.md` |
| ADR-011 | PostgreSQL 持久化采用 SQLAlchemy Core 2.x、psycopg 3 与显式 Alembic 迁移 | 提供清晰的异步事务边界、可审查 DDL，并让 Job 与 Outbox 在同一事务登记 | `code/docs/adr/011-postgresql-persistence-toolkit.md` |
| ADR-012 | 首版本地工件库采用 SHA-256 内容寻址、同文件系统 staging 与排他硬链接原子发布 | 保证同内容稳定引用、拒绝覆盖与调用方宿主路径，并保留 MinIO 后端替换能力 | `code/docs/adr/012-local-content-addressed-artifact-store.md` |
| ADR-013 | PostgreSQL Outbox 到 Redis Streams 采用至少一次交付、稳定事件 ID 和 Redis 内短期原子去重 | 正确认知跨存储崩溃窗口，同时避免等价重试重复追加并要求 T06 保护持久化副作用 | `code/docs/adr/013-at-least-once-outbox-to-redis.md` |
| ADR-014 | CI 使用 Ruff、Pyright 与 pytest 分层门禁，在 PR/`main` 推送/手动触发时以只读权限运行 | 分层覆盖规范、类型与运行行为，把质量检查固化为必过门禁 | `code/docs/adr/014-ci-quality-gate.md` |
| ADR-015 | PostgreSQL Job 租约作为执行权事实来源，Redis pending 仅负责传输与超时接管 | 防止崩溃、ACK 丢失或重复消息造成同一 Job 并发执行 | `code/docs/adr/015-job-leases-and-pending-recovery.md` |
| ADR-016 | 最终 WorkerResult 先与 Job 终态事务落库，再 ACK 或原子转入 dead-letter；具体 Worker 统一复用可靠生命周期 | 在 PostgreSQL/Redis 无分布式事务时保证业务结果唯一并稳定恢复 ACK、死信响应丢失和进程崩溃 | `code/docs/adr/016-worker-result-and-settlement-protocol.md` |

新增或变更决策时，使用 `ADR-NNN` 编号，记录日期、上下文、方案、决定、后果及受影响模块；重大决策应另建 `code/docs/adr/NNN-标题.md`。

## 8. 最近完成记录

### 2026-09-07：完成 T06 Worker 租约与幂等框架

- 负责人：Codex
- 状态：已完成
- 修改文件：`code/packages/worker/`、`code/packages/persistence/`、`code/packages/queue/`、`code/tests/worker/`、`code/tests/persistence/`、`code/tests/queue/`、`code/docs/adr/015-job-leases-and-pending-recovery.md`、`code/docs/adr/016-worker-result-and-settlement-protocol.md`、`code/pyproject.toml`、`code/uv.lock`、`DEVELOPMENT_STATUS.md`
- 已完成：新增不可变 `job_results` 迁移及事务化幂等结果仓储；实现相同结果重放、冲突拒绝、尝试耗尽失败登记；Redis Lua 原子完成 dead-letter 与 ACK；建立可配置并发 Worker SDK，统一 pending 接管、数据库租约、心跳、重试、执行异常归一、最终 ACK、取消和超时强制停止
- 测试与结果：121 个全量 pytest 测试通过，分支覆盖率 90.07%；Ruff、Pyright strict 与 TypeScript 通过；真实 PostgreSQL/Redis 覆盖 ACK 丢失、dead-letter 响应丢失、重复消息、可恢复失败、尝试耗尽、心跳续租、协作/强制停止，以及崩溃后的 pending + 过期租约接管；Dispatcher 镜像重建成功，`0003_job_results` 迁移容器退出码 0
- 问题：无新增；Redis 去重记录为有限 TTL，过期后的死信条目可能重复，但 PostgreSQL `job_results` 保证业务结果唯一
- 阻碍点：无
- 决策：ADR-015、ADR-016
- 下一步：认领 T07，基于现有仓储和工件登记服务实现 FastAPI 项目、工件与任务接口

### 2026-09-07：完成 T06 第一检查点——租约与 Pending 接管原语

- 负责人：Codex
- 状态：进行中
- 修改文件：`code/packages/persistence/`、`code/packages/queue/`、`code/tests/persistence/test_job_leases.py`、`code/tests/queue/test_redis_streams.py`、`code/docs/adr/015-job-leases-and-pending-recovery.md`、`DEVELOPMENT_STATUS.md`
- 已完成：将本地 `main` 快进到 PR #3 并删除本地/远程全部已合并任务分支；创建 `feat/t06-worker-reliability`；实现独占租约、同 owner 幂等领取、续约、释放、过期接管、尝试上限和 Redis `XAUTOCLAIM` pending 转移
- 测试与结果：`pnpm run check` 通过；Ruff 0 问题、Pyright 0 错误、98 个 pytest 测试通过、分支覆盖率 90.61%、TypeScript 通过；定向 PostgreSQL/Redis 测试 17 个通过
- 问题：无新增；Q-002、Q-003 保留
- 阻碍点：无
- 决策：ADR-015
- 下一步：新增不可变 JobResult 并实现 Worker 心跳执行循环、持久化成功后 ACK、失败重试与幂等 dead-letter

### 2026-09-07：完成 T01.1 CI 质量门禁

- 负责人：Codex
- 状态：已完成
- 修改文件：`.github/workflows/quality-gate.yml`、`code/docs/adr/014-ci-quality-gate.md`、`code/pyproject.toml`、`code/package.json`、`code/pnpm-lock.yaml`、`code/uv.lock`、`code/.devcontainer/devcontainer.json`、`code/README.md`，以及为通过 Pyright strict 而修正的 `store.py`、`generate_contracts.py`、`validation.py`、`redis_streams.py`、`database.py`、`main.py`、`DEVELOPMENT_STATUS.md`
- 已完成：以 Ruff（代码规则与低级缺陷）、Pyright（strict、Linux/Python 3.12）、pytest（90% 分支覆盖率，含真实 PostgreSQL/Redis 集成与契约生成漂移检查）和 TypeScript（`tsc --noEmit`）建立分层质量门禁，统一为 `pnpm run check` 与 GitHub Actions 工作流；Mypy 切换为 Pyright 暴露的 6 处 strict 类型问题已以最小范围修正或对第三方 stub 作针对性忽略
- 测试与结果：`pnpm run check` 全链路通过（Ruff 0 问题、Pyright 0 错误、94 个测试通过、分支覆盖率 91.60%、TypeScript 通过）；`uv lock --check` 与 `pnpm install --frozen-lockfile` 确认锁文件与清单一致；核对 `actions/checkout@v7`、`actions/setup-python@v7`、`actions/setup-node@v6` 为有效版本且 `package-manager-cache` 输入受支持
- 问题：无
- 阻碍点：无
- 决策：ADR-014
- 下一步：认领 T06，实现 Worker 消费循环、Job 租约/幂等框架

### 2026-09-07：统一持久化枚举序列化边界

- 负责人：Codex
- 状态：已完成
- 修改文件：`code/packages/persistence/src/vulnweaver_persistence/repositories.py`、`code/tests/persistence/test_repositories.py`、`DEVELOPMENT_STATUS.md`
- 已完成：将 Project、Task、Job 剩余枚举字段从仅支持 `.value` 的序列化改为 `str()`，与 Artifact 行为一致；覆盖 `permission_mode`、`kind`、Task `status/result` 和 Job `kind/status`，避免 T07 透传 Schema 合法字符串时触发 `AttributeError`
- 测试与结果：新增真实 PostgreSQL 回归先在旧实现复现异常，修正后 94 个 Pytest 测试通过，分支覆盖率 91.60%；Ruff、Mypy、契约生成、TypeScript、锁文件与 Compose 配置检查通过
- 问题：无
- 阻碍点：无
- 决策：仓储边界在契约校验后同时接受生成的 StrEnum 与对应合法字符串；无须修改 Schema 或数据库迁移
- 下一步：认领 T06，实现 Worker 消费循环与 Job 租约/幂等框架

### 2026-09-07：完成 T04/T05 Codex Review 核查与修正

- 负责人：Codex
- 状态：已完成
- 修改文件：`code/packages/artifact-store/`、`code/packages/persistence/`、`code/packages/queue/`、`code/apps/dispatcher/`、对应测试、ADR-012、ADR-013、`DEVELOPMENT_STATUS.md`
- 已完成：修复字符串枚举绕过派生谱系约束及其持久化兼容；将重复旧摘要定义为幂等重试并禁止 current version 回退；新摘要目录从父到叶逐级 fsync；Dispatcher 从整批长事务改为单条事件独立事务并统一使用数据库服务器时间；校验 Stream 冗余字段与事件载荷一致性，统一读取边界错误类型；补充两个真实 Dispatcher 并发回归
- 测试与结果：新增用例先在旧实现稳定复现 5 个缺陷，修正后 93 个 Pytest 测试通过，分支覆盖率 91.37%；Ruff、Mypy、契约生成、TypeScript、锁文件与 Compose 配置全部通过；重新构建镜像后迁移容器退出码 0，Dispatcher 正常运行，PostgreSQL/Redis healthy
- 问题：Review 所述 Artifact 初始 `current_version_id` 临时 NULL 已由同一事务和循环外键决定且已有说明；`verify()` 只接受 canonical 引用，返回值不存在非规范化路径；可恢复 Redis 故障维持无限次、有上限间隔的重试，避免可靠 Outbox 静默漏投
- 阻碍点：无
- 决策：补充 ADR-012 的版本指针语义和 ADR-013 的单条事务、数据库时钟及传输重试语义
- 下一步：认领 T06，实现 Worker 消费循环、Job 租约领取/续约/接管、成功结果幂等登记、pending message 回收和 Worker dead-letter

### 2026-09-07：完成 T05 Redis Streams 与 Outbox Dispatcher

- 负责人：Codex
- 状态：已完成
- 修改文件：`code/packages/queue/`、`code/apps/dispatcher/`、`code/packages/persistence/`、`code/tests/queue/`、`code/tests/dispatcher/`、`code/tests/persistence/`、`code/compose.yaml`、`code/.env.example`、`code/pyproject.toml`、`code/uv.lock`、`code/docs/adr/013-at-least-once-outbox-to-redis.md`、`DEVELOPMENT_STATUS.md`
- 已完成：实现 QueueEvent 到 jobs/events Stream 的版本化传输、Redis 7 Lua 原子 event ID 去重与内容冲突检测、消费者组创建/read/ack；扩展 Outbox 迁移以保存 dead-letter 终止态；实现多 Dispatcher 跳过锁行、发布确认、失败退避、恢复重放和可停止轮询；新增迁移与 Dispatcher 容器，按非 root、只读根文件系统、无 Linux capabilities 运行
- 测试与结果：87 个 Pytest 测试通过，分支覆盖率 91.17%；真实 PostgreSQL 16 与 Redis 7 验证投递、ACK、重复发布、冲突、故障退避、dead-letter 和并发领取；Ruff、Mypy、契约生成、TypeScript、锁文件及 Compose 配置通过；Dispatcher 镜像构建成功，迁移容器退出码 0，Dispatcher 实际启动
- 问题：PostgreSQL 与 Redis 无分布式事务，Redis 接收后数据库提交前崩溃仍可能触发重试；ADR-013 明确至少一次语义，Redis TTL 内抑制等价重复，T06 仍须按 Job 幂等键保护持久化副作用
- 阻碍点：无
- 决策：ADR-013
- 下一步：认领 T06，实现 Worker 消费循环、Job 租约领取/续约/接管、成功结果幂等登记、pending message 回收和 Worker dead-letter

### 2026-09-07：完成 T04 本地内容寻址工件库

- 负责人：Codex
- 状态：已完成
- 修改文件：`code/packages/artifact-store/`、`code/tests/artifact_store/`、`code/packages/persistence/`、`code/tests/conftest.py`、`code/pyproject.toml`、`code/uv.lock`、`code/docs/adr/012-local-content-addressed-artifact-store.md`、`DEVELOPMENT_STATUS.md`
- 已完成：实现后端无关 ArtifactStore 协议与本地 CAS；增量计算 SHA-256，以 canonical object ref 管理对象；使用同文件系统 staging、刷盘与排他硬链接发布；拒绝超限、非二进制流、非法引用、路径逃逸和损坏对象；实现 Artifact/ArtifactVersion 数据库读取及对象写入后登记服务，强制派生工件记录父版本、工具身份和生成配置
- 测试与结果：67 个 Pytest 测试通过，分支覆盖率 96.29%；Ruff 与 Mypy 通过；真实 PostgreSQL 测试验证初始工件、内容去重、版本读取、当前版本和派生谱系
- 问题：对象写入成功但数据库事务失败时可能留下安全的未引用对象；ADR-012 明确保留对象并由后续受控 GC 清理，避免误删并发复用内容
- 阻碍点：无
- 决策：ADR-012
- 下一步：完成 T05 Redis Streams 客户端、消费者组基础与 Outbox Dispatcher，并验证投递失败、恢复和重复事件去重

### 2026-09-07：完成 T03 PostgreSQL 迁移与事务仓储

- 负责人：Codex
- 状态：已完成
- 修改文件：`code/packages/persistence/`、`code/tests/persistence/`、`code/pyproject.toml`、`code/uv.lock`、`code/docs/adr/011-postgresql-persistence-toolkit.md`、`DEVELOPMENT_STATUS.md`
- 已完成：建立 PostgreSQL 控制面首批关系模型与可逆 Alembic 迁移；实现异步数据库生命周期、transaction-scoped repositories、结构化持久化错误、请求指纹幂等、Project/ArtifactVersion/Task/Job 仓储、Job/Outbox 原子登记、Outbox 重放状态和追加式 TaskEvent；用外键、唯一约束、状态 CHECK、摘要格式约束和当前工件版本引用保护数据一致性
- 测试与结果：55 个 Pytest 测试通过，分支覆盖率 97.59%；其中 16 个 PostgreSQL 集成/配置测试在独立临时数据库完成 upgrade、Schema 漂移校验、仓储事务场景和 downgrade；Ruff、Mypy、契约生成漂移、TypeScript 严格检查、uv 锁文件和 Compose 配置检查通过
- 问题：Q-003；继续使用 `uv sync --no-editable` 与 `uv run --no-sync` 完成 Windows 中文路径验证
- 阻碍点：无
- 决策：ADR-011
- 下一步：认领 T04，实现本地内容寻址工件库，并把真实 SHA-256、不可变写入和父工件谱系接入 T03 仓储

### 2026-09-07：完成 T02 公共契约与领域规则

- 负责人：Codex
- 状态：已完成
- 修改文件：`code/packages/contracts/`、`code/packages/domain/`、`code/tests/contracts/`、`code/tests/domain/`、`code/pyproject.toml`、`code/uv.lock`、`code/pnpm-lock.yaml`
- 已完成：以 JSON Schema Draft 2020-12 冻结 v1.0.0 实体、API、队列、Worker、`ActionPlan`、`ToolSpec`、`CapabilityProfile` 和 `FindingPolicy`；从同一来源生成 Python/TypeScript 类型；实现运行时契约校验、Task/Job/Run/Poc/Finding 状态机、Task 聚合、证据确认、利用门禁及幂等键规则
- 测试与结果：39 个 Pytest 测试通过，分支覆盖率 98.98%；Ruff、Mypy、JSON Schema 元校验、生成漂移检查和 TypeScript 严格检查通过
- 问题：Q-003；已使用非 editable 安装完成 Windows 本机验证，不影响任务产物
- 阻碍点：无
- 决策：无新增重大架构决策；沿用 ADR-001、ADR-003、ADR-006、ADR-008
- 下一步：认领 T03，依据 v1.0.0 契约建立 PostgreSQL 迁移、仓储与 Job/Outbox 原子事务

### 2026-09-07：明确 Agent 自主 Git 版本管理并建立初始化基线

- 负责人：Codex
- 状态：已完成
- 修改文件：`AGENTS.md`、`README.md`、`DEVELOPMENT_STATUS.md`、`code/docs/adr/010-git-version-control.md`
- 已完成：明确 Git 为唯一版本管理方式、`main` 为集成基线；授权 Agent 自主建分支、暂存并提交任务内变更；创建首次初始化基线提交
- 测试与结果：确认根目录仓库位于 `main`、无嵌套仓库；提交前完成变更范围、忽略文件与敏感信息检查
- 问题：无
- 阻碍点：无
- 决策：ADR-010
- 下一步：认领 T02，并按任务边界自主创建分支和维护提交

## 9. 验证记录

| 日期 | 任务 | 命令/方式 | 结果 | 未覆盖范围 |
|---|---|---|---|---|
| 2026-09-07 | 稳定交接规则 | 核对 `AGENTS.md` 与架构文档、模块拆分及动态台账的职责边界 | 通过 | 尚无业务代码可测试 |
| 2026-09-07 | 文档初始化 | 人工核对架构模块、依赖和目录约束 | 通过 | 尚无代码可测试 |
| 2026-09-07 | T01 Compose | `docker compose -f compose.yaml -f compose.dev.yaml config --quiet`、`up -d`、`ps` | 通过；dev 运行中，PostgreSQL/Redis healthy | 尚未构建业务服务 |
| 2026-09-07 | T01 依赖与质量工具 | `uv sync --frozen --refresh`、`pnpm install --frozen-lockfile`、`ruff check .`、`mypy --version`、`pytest --version`、`pnpm run check` | 通过；国内源生效 | 尚无 Python 源文件与 Node 子项目，因此没有业务测试 |
| 2026-09-07 | T01 服务与安全边界 | `pg_isready`、`redis-cli ping`、检查 `/var/run/docker.sock` | 通过；数据库可连接、Redis 返回 PONG、开发容器未挂载 Docker Socket | Sandbox Runner 尚未实现 |
| 2026-09-07 | Git 版本管理 | `git status --short --branch`、嵌套仓库检查、暂存差异与敏感信息检查 | 通过；当前为 `main`，首次初始化基线已提交 | 未配置或推送远程仓库 |
| 2026-09-07 | T02 Python 单元/契约测试 | `uv run --no-sync pytest --cov --cov-report=term-missing --cov-fail-under=90` | 39 个测试通过；分支覆盖率 98.98% | 未包含数据库或跨服务集成，属于 T03+ 范围 |
| 2026-09-07 | T02 Python 静态检查 | `uv run --no-sync ruff check .`、`uv run --no-sync mypy packages` | 通过；9 个源文件无类型错误 | 无 |
| 2026-09-07 | T02 跨语言契约 | Pytest JSON Schema 元校验及生成 `--check`、`pnpm run check` | 通过；Python/TypeScript 生成文件与 v1.0.0 Schema 一致，TypeScript 严格检查通过 | 尚无 API/队列消费者，消费者契约测试从 T05/T07 开始 |
| 2026-09-07 | T03 PostgreSQL 集成 | `uv run --no-sync pytest tests/persistence -q` | 16 个测试通过；真实 PostgreSQL 临时库完成 upgrade、模型迁移无漂移、事务/幂等/回滚/重放/追加约束和 downgrade | 未模拟 PostgreSQL 进程中断；恢复演练属于 T22 |
| 2026-09-07 | T03 Python 回归与覆盖率 | `uv run --no-sync pytest --cov --cov-report=term-missing --cov-fail-under=90` | 55 个测试通过；分支覆盖率 97.59% | Alembic 环境引导与不可变历史迁移脚本不计逐行覆盖，由迁移集成测试验证 |
| 2026-09-07 | T03 静态与跨语言检查 | `uv run --no-sync ruff check .`、`uv run --no-sync mypy packages`、契约生成脚本 `--check`、`pnpm run check` | 通过；20 个 Python 源文件无类型错误，契约生成物与 TypeScript 严格检查无回归 | 无 |
| 2026-09-07 | T03 依赖与基础设施 | `uv lock --check`、`docker compose -f compose.yaml -f compose.dev.yaml config --quiet`、`docker compose ... ps` | 通过；锁文件有效，PostgreSQL 16 与 Redis 7 均 healthy | 未推送远程或执行生产部署 |
| 2026-09-07 | T04 内容寻址工件库 | `uv run --no-sync pytest --cov --cov-report=term-missing --cov-fail-under=90`、`ruff check .`、`mypy packages` | 67 个测试通过，分支覆盖率 96.29%；流式哈希、原子发布、去重、边界拒绝、完整性校验、谱系和 PostgreSQL 登记均通过 | 未实现未引用对象 GC 与 MinIO 后端；不影响首版本地存储验收 |
| 2026-09-07 | T05 队列与 Dispatcher | `uv run --no-sync pytest --cov --cov-report=term-missing --cov-fail-under=90`、`ruff check .`、`mypy packages apps` | 87 个测试通过，分支覆盖率 91.17%；真实 PostgreSQL/Redis 覆盖发布、去重、read/ack、退避、dead-letter、重放与行锁领取 | Worker pending 接管、租约和执行结果幂等属于 T06 |
| 2026-09-07 | T05 容器交付 | Compose 配置解析、`docker compose ... build dispatcher`、`up -d dispatcher`、日志及 `docker inspect` | 通过；迁移退出码 0，Dispatcher 运行中；用户为 `vulnweaver`、根文件系统只读、capabilities 全部移除、无宿主绑定挂载 | 未执行生产部署或多主机故障演练 |
| 2026-09-07 | T04/T05 Review 回归 | 先运行新增缺陷用例复现，再执行 `pytest --cov`、Ruff、Mypy、契约生成 `--check`、`uv lock --check`、`pnpm run check`、Compose 构建/启动/状态检查 | 93 个测试通过，分支覆盖率 91.37%；双 Dispatcher 在一个实例阻塞时可并发处理另一事件；迁移退出 0、服务健康且安全配置未回退 | 单条发布仍在事务中持有一条行锁和一个连接；高吞吐场景若需把网络 IO 移出事务，应另增带所有者令牌的 Outbox 领取租约 |
| 2026-09-07 | T03 枚举兼容性回归 | 新增合法字符串枚举 PostgreSQL 集成测试后执行全量 `pytest --cov`、Ruff、Mypy、契约生成 `--check`、`uv lock --check`、`pnpm run check` 与 Compose 配置检查 | 94 个测试通过，分支覆盖率 91.60%；Project/Artifact/Task/Job 字符串枚举写入并按生成枚举读回 | 无 |
| 2026-09-07 | T01.1 CI 质量门禁 | `pnpm run check`（Ruff、Pyright strict、pytest `--cov --cov-fail-under=90`、TypeScript `tsc --noEmit`）、`uv lock --check`、`pnpm install --frozen-lockfile`；核对 `actions/checkout@v7`、`actions/setup-python@v7`、`actions/setup-node@v6` 版本有效性与 `package-manager-cache` 输入 | 通过；Pyright 0 错误、94 个测试通过、分支覆盖率 91.60%、契约生成漂移检查经 pytest 通过、锁文件一致 | GitHub Actions 工作流尚未在远端 runner 实跑；平台层必需检查需仓库管理员配置 |
| 2026-09-07 | T01.1 推送前复验与分支推送 | 确认 PostgreSQL/Redis healthy 后执行 `pnpm run check`、`uv lock --check`、`pnpm install --frozen-lockfile`，随后 `git push -u origin chore/ci-quality-gate` | 通过；结果与上一次记录一致（Ruff 0 问题、Pyright 0 错误、94 测试、覆盖率 91.60%、TypeScript 通过、锁文件一致）；分支已推送并建立上游跟踪 | GitHub Actions 仍需通过 PR 或手动触发才会实跑（推送非 `main` 分支不触发）；分支保护必需检查仍待平台配置 |
| 2026-09-07 | T06 租约与 Pending 接管 | `pnpm run check`；定向执行 `pytest tests/persistence/test_job_leases.py tests/queue/test_redis_streams.py -q` | 通过；98 个全量测试、90.61% 分支覆盖率；数据库租约竞争/续约/释放/过期接管/尝试耗尽与 Redis `XAUTOCLAIM` 均通过 | 幂等 JobResult、Worker 心跳循环、最终 ACK 与 dead-letter 尚未实现 |
| 2026-09-07 | T06 Worker 可靠生命周期 | `pnpm run check`；定向执行 Worker/Persistence/Queue 集成测试；`uv lock --check`；Compose 配置解析；重建 Dispatcher 镜像并运行迁移容器 | 通过；121 个全量测试、90.07% 分支覆盖率、Ruff/Pyright/TypeScript 通过；真实 PostgreSQL/Redis 故障注入覆盖结果幂等、ACK/死信响应丢失、重试耗尽、心跳、停止和崩溃接管；迁移退出码 0，Dispatcher 以非 root、只读根文件系统、capabilities 全移除且无宿主绑定挂载运行 | 未构建具体分析 Worker 镜像；由使用 SDK 的 T12/T16/T19/T20 各自交付 |

## 10. 下一步

1. 认领 T07，创建 FastAPI 应用骨架并实现 Project、Artifact、Task 的首批 API。
2. 复用 T03 仓储与 T04 工件登记服务，保持 API DTO 与 v1.0.0 公共 Schema 一致。
3. 为创建任务的幂等键、错误响应、上传边界和健康检查补充 API/集成测试。

## 11. 每次工作结束时的更新模板

复制以下模板到“最近完成记录”顶部，并同步修改其他相关表格：

```markdown
### YYYY-MM-DD HH:mm：<任务包/工作摘要>

- 负责人：<Agent 或人员标识>
- 状态：<进行中/受阻/待验证/已完成>
- 修改文件：<code/ 下的路径列表>
- 已完成：<可验证的完成项>
- 测试与结果：<实际命令、结果；未运行则说明原因>
- 问题：<新发现问题；没有则写“无”>
- 阻碍点：<阻碍、已尝试方案、解除条件；没有则写“无”>
- 决策：<ADR 编号或“无”>
- 下一步：<一个可以直接执行的动作>
```

## 12. Agent 交接检查清单

- [ ] 已确认所有改动都位于 `code/` 或本项目文档范围内。
- [ ] 已记录当前 Git 分支、HEAD 和未提交状态，未混入敏感信息或无关文件。
- [ ] 已检查工作区现有改动，未覆盖他人的工作。
- [ ] 已更新任务状态和完成内容。
- [ ] 已记录实际测试结果和未覆盖范围。
- [ ] 已记录问题、阻碍点及解除条件。
- [ ] 已记录新增决策和受影响模块。
- [ ] 已给出下一位 Agent 可直接执行的下一步。
