# Agent 动态交接台账

> 本文件只维护当前进度、问题、阻碍、决策摘要、验证结果和下一步。稳定开发规则见 `AGENTS.md`；架构依据为 `系统架构设计与技术选型.md`，实现任务依据为 `系统实现模块拆分.md`。开始工作前必须阅读 `AGENTS.md` 和本文件，结束或交接前必须更新本文件。

## 1. 项目目标

构建一个面向已授权源码仓库和 x86/x64 ELF/PE 二进制的软件漏洞挖掘系统。系统通过智能体编排静态分析、逆向分析、模糊测试、独立复核、最小复现和可选利用验证，并输出可追溯的 Finding、证据链与报告。

## 2. 当前工程状态

- **项目名称**：VulnWeaver（漏洞织鉴）
- **当前阶段**：P2 源码静态分析 MVP 进行中；T13/T14 已完成，T15 Finding、Evidence 与独立复核正在实现
- **总体状态**：控制面、策略、模型访问、可恢复编排、源码导入、静态工具和 PAIR 源码查询链路已形成；正在建设 Finding、Evidence 与独立复核路径
- **最后更新**：2026-09-09 00:40（Asia/Shanghai）
- **代码目录**：`code/` 已初始化 Python/TypeScript 工作区、Dev Container 与 Compose 基础设施
- **版本管理**：Git；远端 `origin` 指向 `NTFago/VulnWeaver`；当前开发分支为 `feat/t15-finding`，未推送或合并本轮修复
- **稳定开发规则**：根目录 `AGENTS.md` 已建立
- **当前负责人**：Codex；已认领 T15，正在实现 Finding、Evidence 与复核持久化

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
| T01.2 CI 触发去重 | 已完成 | Codex | 移除 `push: main` 触发，保留 Pull Request 与手动触发；同步 ADR-014，避免合并后对已检查变更重复运行 | 无；仓库应禁止绕过必需检查直接推送 `main` | 2026-09-08 |
| T06 Worker 租约与幂等框架 | 已完成 | Codex | 首轮实现与 Review 修正；第二轮完成租约唯一 fencing token、重试退避写入 PostgreSQL 调度、许可等待不 ACK、fresh/PEL 公平领取轮换、心跳重试与结算异常恢复、结果指纹排序、优雅释放退款，并清理只读领取行锁与死信脚本无效 XPENDING | 无 | 2026-09-08 |
| T07 FastAPI 首批控制面 API | 已完成 | Codex | 完成 PR #5 审计修正与个人认证重构：版本化 Cookie/CSRF 会话、锁定和有界 Argon2、幂等改密与会话上限；流式上传前置限额、服务自有暂存和冲突无孤儿；API 只投递 `task.requested`；并发取消单次迁移；统一错误、就绪检查、OpenAPI 和 ADR 已补齐 | 无；`task.requested` 消费与初始 Job 创建属于 T11 编排职责 | 2026-09-08 |
| T08 Svelte 项目与任务页面 | 已完成 | Codex | Svelte 5 工作台接入登录/首次改密、项目授权范围、流式样本上传、任务投递/取消、Job 及 WebSocket 事件恢复；完成响应式状态、同源 Nginx 代理和非 root 容器交付 | 更完整的 Finding/报告/可观测工作台属于 T22 | 2026-09-08 |
| Git 分支清理 | 已完成 | Codex | 确认 T06/T07/T08 均已合并到 `origin/main`，本地 `main` 快进到 `673c477`，删除 3 个本地及 3 个远程已完成分支，并清理过期 `origin/pr/5` 引用 | 无 | 2026-09-08 |
| T09 ToolSpec 与 Policy Engine | 已完成 | Codex | 实现精确版本 Tool Registry、JSON ToolSpec 加载、ActionPlan 校验、结构化策略拒绝/许可等待、资源与安全边界校验及可查询审计记录 | 无；持久化审计后端由后续编排/观测任务接入 | 2026-09-08 |
| T10 模型访问适配与运行记录 | 已完成 | Codex | 实现 OpenAI 兼容 HTTP 适配、规划/审计/复核/报告模型档位路由、超时/重试/限流/远程失败降级、结构化输出修复、可配置脱敏和 AgentRun 记录 | 无；持久化 AgentRun 已由 T11 接入 | 2026-09-08 |
| T11 LangGraph 主流程与检查点 | 已完成 | Codex | 实现可恢复 LangGraph 节点、真实 Redis `task.requested` 消费、fresh/PEL 公平接管、输入归属校验、源码/二进制管线选择、Policy Engine 门禁、等待许可和初始 Job/Outbox 事务登记；新增 AgentRun/Checkpoint 迁移与仓储及可运行服务镜像；T12 已提供源码 ToolSpec 并在 Compose 启用 | T16 提供二进制 ToolSpec 后启用二进制首个 Job | 2026-09-08 |
| T12 安全导入与 tree-sitter 索引 | 已完成 | Codex | 完成安全导入、tree-sitter 索引、SourceImportExecutor、ToolSpec、analysis-worker 和 Compose 全链路；Review 修复将解压/索引移出事件循环、拒绝文件/目录祖先冲突、按 ToolSpec 必填项注入参数、兼容字符串 JobKind，并以 ToolSpec 作为重试策略唯一来源 | 无；受控未引用对象 GC 属于工件存储后续运维能力，Semgrep/cppcheck 属于 T13 | 2026-09-08 |
| T13 Semgrep/cppcheck 适配 | 已完成 | Codex | 实现固定参数、无 Shell 的 Semgrep/cppcheck 适配；新增 `StaticAnalysisResult`/诊断/工具运行契约；源码导入成功后按 CapabilityProfile 创建幂等静态分析 Job；静态结果作为不可变派生工件保存并保留父工件与 ToolSpec 镜像摘要 | 无；T14 负责 PAIR 源码导入与查询 | 2026-09-08 |
| T14 PAIR 源码导入与查询 | 已完成 | Codex | 新增 PAIR Function/Node/Edge/Raw v1 契约；新增 `vulnweaver-pair` 包、0009 关系表迁移、幂等仓储、函数/位置/调用邻域查询；源码导入 Worker 成功后自动写入 PAIR，并将原始结果、工具身份和 `pair_raw_id` 保留在图元素属性中 | 无；T15 接入 Finding、Evidence 与独立复核 | 2026-09-08 |
| T15 Finding、Evidence 与复核 | 进行中 | Codex | 已完成 Evidence `0010`、候选 Finding/FindingEvidence `0011`、Review 历史 `0012` 关系表与仓储；Review 默认拒绝无确认授权的 `confirmed` 状态，保留 Review 历史并更新 Finding 状态；容器内迁移/策略定向测试通过 | 将领域 ConfirmationContext 从编排层接入 Review，并实现 StaticAnalysisResult/PAIR 到候选 Finding/Evidence 的投影 | 2026-09-08 |
| T15-R1 静态分析与 PAIR 审计修正 | 已完成 | Codex | PAIR 调用边按关系身份聚合调用点并消除名称碰撞误连；Review 串行锁定并按不可变历史重建状态；规范化事实时间戳；导入/静态持久化异常返回终态；修正静态谱系、输出上限、严重度和 Worker 外网隔离 | 无 | 2026-09-09 |


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
| D-004 | 首版身份认证 | 个人账号登录，不提供团队或管理员体系 | 项目创建者为唯一所有者；无成员、角色和 RBAC | P1 | 已确认（用户 2026-09-08 明确） |
| D-005 | MVP 质量门禁 | 风险分层定向验证；里程碑再跑全量 | 覆盖率门槛 80%，保留契约、安全、事务和并发关键检查 | P1 | 已确认（用户 2026-09-08 明确） |

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
| ADR-014 | CI 使用 Ruff、Pyright 与 pytest 分层门禁，在 PR/手动触发时以只读权限运行，`main` 依靠分支保护复用 PR 检查结果 | 分层覆盖规范、类型与运行行为，同时避免 PR 合并后重复运行 | `code/docs/adr/014-ci-quality-gate.md` |
| ADR-015 | PostgreSQL Job 租约作为执行权事实来源，Redis pending 仅负责传输与超时接管 | 防止崩溃、ACK 丢失或重复消息造成同一 Job 并发执行 | `code/docs/adr/015-job-leases-and-pending-recovery.md` |
| ADR-016 | 最终 WorkerResult 先与 Job 终态事务落库；获准重试的失败按 attempt 追加审计；之后 ACK、保留 pending 或原子转入 dead-letter | 在 PostgreSQL/Redis 无分布式事务时保证结果唯一、失败可追溯并稳定恢复 ACK、死信响应丢失和进程崩溃 | `code/docs/adr/016-worker-result-and-settlement-protocol.md` |
| ADR-017 | 单个人账号使用 Argon2id、数据库会话、HttpOnly Cookie、会话绑定 CSRF、锁定和幂等改密 | 不引入 RBAC 的前提下建立可多实例、可撤销且抗资源滥用的浏览器认证边界 | `code/docs/adr/017-personal-browser-authentication.md` |
| ADR-018 | API 只事务登记 `CREATED` Task、`task.requested` 与 Outbox，初始 Job 由编排层创建 | 防止接入层绕过 LangGraph 与 Policy Engine，保持控制面职责边界 | `code/docs/adr/018-task-intake-owned-by-orchestrator.md` |
| ADR-019 | LangGraph 节点结果追加到 PostgreSQL 检查点；初始 Job/Outbox 使用确定性标识幂等重放；永久结果后 ACK，瞬时失败保留 Pending | 保证 task.requested 至少一次投递下的节点恢复、策略门禁和 Job 唯一性 | `code/docs/adr/019-task-orchestration-checkpoints.md` |

新增或变更决策时，使用 `ADR-NNN` 编号，记录日期、上下文、方案、决定、后果及受影响模块；重大决策应另建 `code/docs/adr/NNN-标题.md`。

## 8. 最近完成记录

### 2026-09-09 00:40：完成 T15-R1 静态分析与 PAIR 审计修正

- 负责人：Codex
- 状态：已完成
- 修改文件：`code/packages/pair/`、`code/packages/persistence/`、`code/packages/source-analysis/`、`code/packages/orchestrator/`、`code/tests/pair/`、`code/tests/evidence/`、`code/tests/finding/`、`code/tests/source_analysis/`、`code/compose.yaml`
- 已完成：撤销不存在模块的 Orchestrator 导出；PAIR 将同一 caller/target 的多调用点聚合成一个关系边并在 `call_sites` 保留位置，使用限定名、调用者作用域和同文件唯一候选解析目标，歧义不再按插入顺序误连；Review 使用 `FOR UPDATE` 串行化并按有序不可变历史重建 `review_ids`/状态；Evidence/Finding/Review 时间戳统一规范化；源码导入和静态执行将持久化异常转为结构化 WorkerResult，已发布索引在后续失败时仍写入结果；静态结果改以实际扫描的源码归档为父版本并记录索引版本；子进程输出总量限制为预算与 16 MiB 的较小值，最低级 cppcheck 严重度修正为 info；工具子进程清理控制面凭据环境，分析 Worker 只接入禁外网的内部网络。
- 测试与结果：定向 PostgreSQL 测试 33 个通过；`pnpm run check` 全量 208 个测试通过、总覆盖率 85.79%，Ruff/Pyright/TypeScript/Svelte 检查通过；Compose 配置解析和 analysis-worker 镜像构建通过；运行态验证 Worker 仅有 `analysis-plane`、可连接 PostgreSQL，连接外部 `1.1.1.1:53` 返回不可达。
- 问题：无
- 阻碍点：无
- 决策：无新增 ADR；保持静态工具由固定参数适配器执行，并在当前 Worker 部署边界增加内部网络和最小环境防护。
- 下一步：继续 T15 的 StaticAnalysisResult/PAIR 到候选 Finding/Evidence 投影及 ConfirmationContext 编排。

### 2026-09-08 23:42：完成 T15 第三检查点——Review 历史与确认门禁

- 负责人：Codex
- 状态：进行中
- 修改文件：`code/packages/persistence/`、`code/tests/finding/`、`code/tests/persistence/test_migrations.py`
- 已完成：新增 `0012_review_history` 迁移和 Review 表；实现 Review 历史查询与 Finding 状态更新；`confirmed` Review 必须由上层传入 `confirmation_allowed=True`，Persistence 层不自行信任模型输出；不满足授权时结构化拒绝并保持 Candidate 状态。
- 测试与结果：现有 Dev Container 内 PostgreSQL 服务名配置下，Finding/Review/迁移定向测试 3 个通过；Ruff 通过；主 PostgreSQL 已升级至 `0012_review_history`，`reviews` 表已确认存在；修复 Persistence 对 Domain 包的错误运行时依赖，Dispatcher 迁移容器可正常启动。
- 问题：静态诊断到候选 Finding/Evidence 的投影尚未接入；ConfirmationContext 仍需由上层复核编排生成。
- 阻碍点：无
- 决策：Persistence 只接受显式 `confirmation_allowed`，避免执行层自行把模型或 Review 文本解释为确认依据。
- 下一步：实现静态工具/PAIR 结果到候选 Finding/Evidence 的确定性投影，并在编排层调用领域 ConfirmationPolicy。

### 2026-09-08 23:30：完成 T15 第二检查点——候选 Finding 关系持久化

- 负责人：Codex
- 状态：进行中
- 修改文件：`code/packages/persistence/`、`code/tests/finding/`、`code/tests/persistence/test_migrations.py`
- 已完成：新增 `0011_finding_candidates` 迁移和 `findings`/`finding_evidence` 表；实现候选 Finding 创建、按 Task 查询、FindingEvidence 幂等链接；保留候选状态，不允许该检查点直接确认漏洞。
- 测试与结果：使用 `vulnweaver-dev-1` 容器执行；容器内 Evidence/Finding/迁移定向测试 3 个通过；Ruff 和变更持久化模块 Pyright 通过；Compose 主 PostgreSQL 已升级到 `0011_finding_candidates`，三张新表已确认存在。
- 问题：Review 历史、确认策略调用和静态诊断到候选 Finding 的投影尚未接入。
- 阻碍点：无
- 决策：Finding 默认只保存 `candidate`；确认必须由后续 Review 结合 EvidencePolicy 完成。
- 下一步：实现 Review 历史与确认策略门禁，再将 `StaticAnalysisResult` 投影为 Finding/Evidence。

### 2026-09-08 23:10：完成 T15 第一检查点——Evidence 持久化

- 负责人：Codex
- 状态：进行中
- 修改文件：`code/packages/persistence/`、`code/tests/evidence/`、`code/tests/persistence/test_migrations.py`
- 已完成：新增 `0010_evidence` 迁移和 `evidence` 事实表；实现不可变、按 ID 幂等的 `EvidenceRepository.create/get/list_for_input`；增加 SHA-256、Evidence 类型/强度和可选命令摘要约束；补充迁移无漂移与 Evidence 重放测试。
- 测试与结果：使用现有 Dev Container `vulnweaver-dev-1`，设置容器内 PostgreSQL 服务名 `postgres` 执行；Evidence/迁移定向测试 3 个通过，Ruff 通过；未使用宿主机临时 Python 环境。
- 问题：Finding/FindingEvidence/Review 尚未实现。
- 阻碍点：无
- 决策：Evidence 作为不可变事实保存；确认、复核和 Finding 状态迁移留在后续检查点。
- 下一步：在同一迁移链路上实现 Finding/FindingEvidence 的最小候选导入和查询，再加入 Review 策略门禁。

### 2026-09-08 22:46：完成 T14 PAIR 源码导入与查询

- 负责人：Codex
- 状态：已完成
- 修改文件：`code/packages/contracts/`、`code/packages/pair/`、`code/packages/persistence/`、`code/packages/source-analysis/`、`code/apps/analysis-worker/`、`code/deploy/tool-specs/*.json`、`code/pyproject.toml`、`code/uv.lock`、`code/tests/pair/`、`code/tests/persistence/`、`code/tests/contracts/`
- 已完成：新增 `PairFunction`、`PairNode`、`PairEdge`、`PairRaw` v1 契约；新增 PostgreSQL `pair_functions`、`pair_nodes`、`pair_edges`、`pair_raw` 表及索引；实现幂等 PAIR 仓储、源码函数/调用边导入、函数列表、源码位置和有界调用邻域查询；源码导入 Worker 成功后自动导入 PAIR；节点、函数和边保存 `pair_raw_id`，原始结果绑定工具身份与工件版本。
- 测试与结果：全量 pytest **198 个通过**、1 个既有 Starlette 弃用警告；T14/迁移/契约定向测试 14 个通过；Ruff 全仓库通过；变更 Python 模块 Pyright 0 错误；contracts TypeScript `tsc --noEmit` 通过；契约生成检查、`uv lock --check`、Compose 配置解析通过；数据库已升级至 `0009_pair_tables`；analysis-worker 镜像构建成功，最终摘要为 `sha256:0041518fd3398da354721fd5b0557ba6e01e553e460724399283dbb29a021897`，Worker 以 UID 10001 启动。
- 问题：Windows 工作区含中文路径时直接使用 uv editable `.pth` 仍受 GBK 读取问题影响；验证继续使用无 editable 临时环境。
- 阻碍点：无
- 决策：无新增重大架构决策；PAIR 关系表沿用 PostgreSQL 事实源，原始输出仍通过 CAS 工件引用保存。
- 下一步：认领 T15，实现 Finding、Evidence、Review 持久化与静态工具/PAIR 结果消费。

### 2026-09-08 22:16：完成 T13 Semgrep/cppcheck 适配与静态 Job 链路

- 负责人：Codex
- 状态：已完成
- 修改文件：`code/packages/contracts/`、`code/packages/source-analysis/`、`code/apps/analysis-worker/`、`code/deploy/tool-specs/`、`code/compose.yaml`、`code/uv.lock`、`code/tests/contracts/`、`code/tests/source_analysis/`
- 已完成：新增 `StaticAnalysisDiagnostic`、`StaticToolRun`、`StaticAnalysisResult` v1 契约；实现固定可审计参数、无 Shell 的 Semgrep/cppcheck 适配与 JSON/XML 归一化；统一高/中/低严重性、CWE、源码位置、工具版本、退出码及 `executable_not_found`/`rules_not_installed`/`language_not_detected` 等能力缺失原因；源码导入成功后按语言能力创建 Semgrep/cppcheck 静态分析 Job，使用确定性幂等键和同事务 Outbox；静态结果按父版本、工具身份和镜像摘要登记为不可变派生工件；分析 Worker 镜像安装 Semgrep 1.130.0 与 cppcheck 2.17.1，关闭 Semgrep metrics/version check，并挂载只读 ToolSpec/rule 配置。
- 测试与结果：Ruff 全仓库通过；变更文件 Pyright 0 错误；契约 TypeScript `tsc --noEmit` 通过；契约/静态适配/调度/源码导入定向测试 30 个通过；全量 pytest 196 个通过、1 个既有 Starlette 弃用警告；`uv lock --check`、Compose 配置解析通过；`docker compose ... build analysis-worker` 成功，镜像摘要为 `sha256:4cfc83f73948a3dd2cddada0d8553361c7a97660353d642362d0e72eddf68b68`，容器以 UID 10001 启动，真实 Semgrep/cppcheck 样本扫描产生结构化输出。
- 问题：Windows 工作区含中文路径时，直接使用 uv editable `.pth` 仍受 GBK 读取问题影响；本轮使用无 editable 的临时环境执行验证，不改变项目代码约束。
- 阻碍点：无
- 决策：无新增重大架构决策；沿用 ADR-012/013/015/016/019 的不可变工件、Outbox、租约、Worker 结算和可恢复编排语义。
- 下一步：认领 T14，实现 PAIR 源码导入与按函数/调用邻域查询，并为 T15 Finding/Evidence 消费静态工具结果预留稳定输入。

### 2026-09-08 21:10：认领 T13 并清理本地开发分支

- 负责人：Codex
- 状态：进行中
- 修改文件：`DEVELOPMENT_STATUS.md`；后续实现预计位于 `code/packages/source-analysis/`、`code/apps/analysis-worker/`、`code/packages/orchestrator/`、`code/deploy/tool-specs/` 及对应测试
- 已完成：刷新远端引用，确认 T09-T12 四条本地功能分支均已进入 `origin/main`；本地 `main` 快进至 `b7d687d` 后删除旧分支，并创建 `feat/t13-static-tools`；完成 T13 架构、模块边界和现有实现核查
- 测试与结果：Git 合并关系检查通过；工作树在开始实现前无未提交改动
- 问题：无
- 阻碍点：无
- 决策：沿用既有 ToolSpec、Policy Engine、Worker 可靠结算和原始工件不可变约束，不新增重大架构决策
- 下一步：先添加失败优先的 Semgrep/cppcheck 适配器测试，再实现结构化结果、能力缺失和静态分析 Job 执行入口

### 2026-09-08 20:46：完成 T01.2 CI 触发去重

- 负责人：Codex
- 状态：已完成
- 修改文件：`.github/workflows/quality-gate.yml`、`code/docs/adr/014-ci-quality-gate.md`、`DEVELOPMENT_STATUS.md`
- 已完成：移除质量门禁的 `push: main` 触发，保留 Pull Request 与手动触发；合并 PR 后不再对同一变更重复启动。
- 测试与结果：使用 PyYAML BaseLoader 成功解析 Workflow，断言触发器精确为 `pull_request` 和 `workflow_dispatch`，并确认 `push` 不存在；`git diff --check` 通过。
- 问题：若仓库允许直接推送 `main`，该推送不再自动运行 CI；应将 `Python quality gate` 保持为必需检查并禁止直接推送。
- 阻碍点：无。
- 决策：更新 ADR-014。
- 下一步：认领 T13，实现 Semgrep/cppcheck 适配、结构化能力缺失结果及源码静态工具 Job 编排。

### 2026-09-08 20:31：完成 T12 Review 正确性修复

- 负责人：Codex
- 状态：已完成
- 修改文件：`code/packages/source-analysis/src/vulnweaver_source_analysis/`、`code/packages/orchestrator/src/vulnweaver_orchestrator/flow.py`、`code/tests/source_analysis/test_source_import.py`、`code/tests/orchestrator/test_orchestrator.py`、`code/deploy/tool-specs/source-import.json`、`DEVELOPMENT_STATUS.md`
- 已完成：将归档解压、tree-sitter 索引和契约校验移入工作线程，避免阻塞 Worker 心跳；每次索引创建独立 Parser 集合以支持并发线程；在写盘前双向拒绝文件/目录祖先路径冲突；JobKind 改用值比较；仅当 ToolSpec `command_schema.required` 声明 `artifact_version_id` 时自动注入；删除无效的 `InitialJobPolicy.retry_policy`，Job 统一使用所选 ToolSpec 的重试策略。
- 测试与结果：定向源码分析/编排 PostgreSQL 集成测试 27 个通过；Dev Container `pnpm run check` 与 `uv lock --check` 通过，191 个 pytest 全部通过、总覆盖率 86.77%，Ruff/Pyright/TypeScript/Svelte 均通过；重建 orchestrator/analysis-worker 后服务正常启动，ToolSpec、构建镜像与运行容器摘要一致；真实 Compose 任务得到成功 Import Job、3 文件、3 函数、2 调用边及 C/Python 索引，Job 使用 ToolSpec 的 2 秒退避和 timeout/environment/dependency 重试白名单。
- 问题：Review #5 所述“对象先于数据库事务写入”是 ADR-012 的既定一致性顺序；派生输出确定且 CAS 按摘要去重，回归确认幂等重放不会增加物理对象。事务失败留下的安全未引用对象继续由后续受控 GC 处理，本次不扩展功能范围。
- 阻碍点：无。
- 决策：沿用 ADR-012、ADR-015、ADR-016 和 ADR-019；未引入新的重大架构决策。
- 下一步：认领 T13，实现 Semgrep/cppcheck 适配、结构化能力缺失结果及源码静态工具 Job 编排。

### 2026-09-08 19:34：完成 T12 安全导入与 tree-sitter 源码索引

- 负责人：Codex
- 状态：已完成
- 修改文件：`code/packages/source-analysis/`、`code/apps/analysis-worker/`、`code/deploy/tool-specs/source-import.json`、`code/packages/contracts/`、`code/packages/orchestrator/`、`code/packages/persistence/`、迁移 `0008_job_tool_identity.py`、`code/tests/source_analysis/`、`code/tests/orchestrator/test_orchestrator.py`、`code/compose.yaml`、`code/pyproject.toml`、`code/uv.lock`、`DEVELOPMENT_STATUS.md`
- 已完成：安全导入 ZIP/TAR，拒绝路径穿越、绝对路径、符号链接、特殊文件、跨平台危险路径、超限文件和压缩炸弹；忽略 Git hooks、`.gitmodules` 且不执行仓库内容；用 tree-sitter 索引 C/C++/Python/Java 文件、摘要、函数/方法、参数、位置和调用关系，生成语言、构建系统与 CapabilityProfile；SourceImportExecutor 从 CAS 读取原工件并登记带父版本、工具版本和镜像摘要的不可变派生索引；修复 Orchestrator 缺少 `vulnweaver-domain` 容器依赖和策略参数未传入 Job 的缺陷；修复派生工件幂等重放的事务中止与非确定时间戳；启用 orchestrator/analysis-worker Compose 服务。
- 测试与结果：Dev Container `pnpm run check` 与 `uv lock --check` 通过；185 个 pytest 全部通过，总覆盖率 86.55%，Ruff/Pyright/TypeScript/Svelte 均通过；定向 Orchestrator/源码分析 PostgreSQL 测试 21 个通过；镜像构建成功且 ToolSpec 摘要与 `vulnweaver-analysis-worker:dev` 镜像 ID 一致；隔离 Compose 栈完成“HTTP 上传源码 → task.requested → Orchestrator → Import Job → analysis-worker → 派生索引工件”真实链路，样本得到 3 文件、3 函数、1 调用边及 C/Python/CMake 能力信息；服务以非 root、只读根文件系统、移除全部 capabilities、无 Docker Socket 运行。
- 问题：Task 在首个 Import Job 成功后仍保持 `VALIDATING`，因为 T13-T15 尚未实现后续静态分析、Finding 聚合与 Task 终态；不影响 T12 导入索引验收。
- 阻碍点：无。
- 决策：沿用 ADR-012、ADR-015、ADR-016、ADR-018、ADR-019；未引入新的重大架构决策。
- 下一步：认领 T13，实现 Semgrep/cppcheck 适配、结构化能力缺失结果及源码静态工具 Job 编排。

### 2026-09-08：完成 T11 LangGraph 主流程与持久化检查点

- 负责人：Codex
- 状态：已完成
- 修改文件：`code/packages/orchestrator/`、`code/apps/orchestrator/`、`code/packages/persistence/`、迁移 `0007_agent_runs_checkpoints`、`code/tests/orchestrator/`、`code/tests/persistence/test_agent_runs_checkpoints.py`、`code/tests/persistence/test_migrations.py`、`code/pyproject.toml`、`code/uv.lock`、`code/docs/adr/019-task-orchestration-checkpoints.md`、`DEVELOPMENT_STATUS.md`
- 已完成：建立 LangGraph 输入校验、管线选择、初始策略判定和 Job 持久化节点；从最新 PostgreSQL 检查点之后恢复；以 advisory lock 追加检查点序号；真实消费并 ACK `task.requested`，交替处理 fresh 与 `XAUTOCLAIM` pending；永久失败写 Task 后 ACK，瞬时异常保留 pending；确定性 Job/事件/幂等标识覆盖“Job 已提交、检查点未提交”崩溃窗口；策略许可等待只创建 `waiting_permission` Job，不写执行 Outbox；新增 AgentRun 与检查点 PostgreSQL 仓储；提供只从受信 ToolSpec 目录加载的非 root orchestrator 服务镜像。
- 测试与结果：Dev Container 内 `pnpm run check` 通过；171 个 pytest 全部通过、总覆盖率 87.53%；Ruff 通过、Pyright 0 错误、TypeScript/Svelte 通过、契约生成漂移检查及 `uv lock --check` 通过；定向 PostgreSQL/Redis 编排与迁移测试 10 个通过；真实 Redis 消费/ACK、持久化中间节点恢复、幂等重放、策略拒绝和许可等待均通过；Dispatcher 迁移镜像将现有数据库升级到 `0007_agent_runs_checkpoints`；`vulnweaver-orchestrator:dev` 构建成功并以 UID 10001 非 root 运行。
- 问题：具体 Worker ToolSpec 必须携带真实镜像摘要；因此不在 T11 为未交付的分析镜像伪造摘要，Compose 中 orchestrator 服务待 T12/T16 提供对应 ToolSpec 后启用。
- 阻碍点：无。
- 决策：ADR-019。
- 下一步：认领 T12，实现安全归档导入、tree-sitter 函数索引、source-import ToolSpec 与 analysis-worker 镜像，并启用源码编排链路。

### 2026-09-08：完成 T10 模型访问适配与运行记录

- 负责人：Codex
- 状态：已完成
- 修改文件：`code/packages/model-gateway/`、`code/packages/contracts/src/vulnweaver_contracts/schemas/v1/contracts.schema.json`、`code/packages/contracts/src/vulnweaver_contracts/generated.py`、`code/packages/contracts/typescript/index.ts`、`code/pyproject.toml`、`code/uv.lock`、`code/tests/model_gateway/test_model_gateway.py`、`DEVELOPMENT_STATUS.md`
- 已完成：新增不依赖厂商 SDK 的 OpenAI 兼容 `chat/completions` HTTP 适配；支持规划、批量审计、复核、报告四类模型档位及远程/本地 fallback；实现有界超时、指数退避重试、全局最小请求间隔限流、HTTP 429/5xx 降级；结构化 JSON 输出契约校验与最多 3 次修复；默认及自定义敏感信息脱敏；安全截断修复上下文；记录提示哈希、输入/结果引用、模型、token、耗时、决策序列和结构化失败到 AgentRun；新增可幂等的内存 AgentRun recorder。AgentRun v1 增加可选 `duration_ms` 与 `result_refs`，保持旧记录兼容。
- 测试与结果：Dev Container 内 `pnpm run check` 通过；163 个 pytest 全部通过、总覆盖率 87.68%；Ruff 通过、Pyright 0 错误、TypeScript/Svelte 通过、契约生成漂移检查通过、`uv lock --check` 通过；PostgreSQL/Redis 集成测试均通过。
- 问题：完整检查产生既有 FastAPI/Starlette 上游弃用警告，不影响运行；AgentRun 当前默认内存记录器，数据库迁移和查询适配留给 T11/M17。
- 阻碍点：无。
- 决策：AgentRun 新增可选字段而非修改 required 集合，保持 v1 历史任务回放兼容；沿用 ADR-005 的 OpenAI 兼容协议，不引入具体厂商 SDK。
- 下一步：认领 T11，实现 `task.requested` 消费、LangGraph 编排骨架、检查点和首个经 Policy Engine 校验的 Job。

### 2026-09-08：完成 T09 ToolSpec 与 Policy Engine

- 负责人：Codex
- 状态：已完成
- 修改文件：`code/packages/tool-runtime/`、`code/packages/tool-runtime/pyproject.toml`、`code/pyproject.toml`、`code/uv.lock`、`code/tests/tool_runtime/test_tool_runtime.py`、`DEVELOPMENT_STATUS.md`
- 已完成：新增精确 `name` + `version` 注册的不可变 Tool Registry；支持单个/数组/目录 JSON ToolSpec 加载与结构校验；Policy Engine 只接受契约合法 ActionPlan，校验工具注册、参数 Schema、输入工件类型、绝对/穿越路径、命令/容器/提权字段、网络双重白名单、资源预算和审批模式；输出不含任意命令字符串的结构化 `ScheduledToolCall`；每个步骤生成可查询审计记录；`FULL_ACCESS` 仅跳过审批等待，不绕过安全策略。
- 测试与结果：Dev Container 内定向 9 个测试通过；Ruff 通过；Pyright 0 错误；使用 PostgreSQL/Redis 服务地址运行 `pnpm run check` 通过，156 个 pytest 全部通过、总覆盖率 89.49%，Svelte/TypeScript 通过，`uv lock --check` 通过。
- 问题：完整检查产生既有 FastAPI/Starlette 上游弃用警告，不影响运行；审计默认使用内存实现，持久化接入留给编排/观测任务。
- 阻碍点：无。
- 决策：无新增重大架构决策；沿用公共 v1 ToolSpec/ActionPlan 契约和现有控制面/执行面边界。
- 下一步：认领 T10，实现 OpenAI 兼容模型访问适配、超时/重试/结构化输出和 AgentRun 运行记录。

### 2026-09-08：清理已合并的本地与远程开发分支

- 负责人：Codex
- 状态：已完成
- 修改文件：`DEVELOPMENT_STATUS.md`；Git refs（本地与 `origin`）
- 已完成：执行 `git fetch --prune origin`；确认 T06、T07、T08 分支均已合并至 `origin/main`；将本地 `main` 快进至 `673c477`；删除本地 `feat/t06-worker-reliability`、`feat/t07-api`、`feat/t08-ui` 及对应远程分支；清理已关闭 PR 的 `origin/pr/5` 跟踪引用
- 测试与结果：Git 状态、分支合并关系、远程分支列表复核通过；当前仅保留本地 `main` 与远程 `origin/main`
- 问题：无
- 阻碍点：无
- 决策：无新增重大架构决策
- 下一步：认领 T09，实现 Tool Registry 与 Policy Engine，为 T11 编排提供强制策略门禁
### 2026-09-08：完成 T08 Svelte 个人工作台与控制面 MVP

- 负责人：Codex
- 状态：已完成
- 修改文件：`code/apps/web/`、`code/compose.yaml`、`code/compose.dev.yaml`、`code/pnpm-workspace.yaml`、`code/pnpm-lock.yaml`、`DEVELOPMENT_STATUS.md`
- 已完成：建立 Svelte 5 + TypeScript + Vite 工作台；接入真实 Cookie/CSRF 认证、首次改密、Project/Artifact/Task/Job API 与任务事件 WebSocket；实现加载、空、错误、成功、禁用及移动端状态；使用同源 Nginx 隔离浏览器与 API，Web 容器非 root、只读根文件系统且移除 capabilities
- 测试与结果：`pnpm run check` 通过，147 个 pytest 通过、总覆盖率 89.45%、Ruff/Pyright/Svelte/TypeScript 无错误；`pnpm --filter @vulnweaver/web build`、Compose 配置解析、`docker compose ... build web`、`uv lock --check` 通过
- 问题：未新增低价值 UI 单测；实际浏览器 E2E 与更完整工作台留待 T22 里程碑集中验证
- 阻碍点：无
- 决策：无新增重大架构决策；沿用 ADR-002、ADR-017、ADR-018
- 下一步：认领 T09，实现 Tool Registry 与 Policy Engine，为 T11 编排提供强制策略门禁

### 2026-09-08：完成 T07 PR #5 审计修正与认证重构

- 负责人：Codex
- 状态：已完成
- 修改文件：`code/apps/api/`、`code/packages/contracts/`、`code/packages/persistence/`、`code/packages/artifact-store/`、`code/tests/`、`code/docs/adr/`、`code/compose.yaml`、根目录设计与开发规则文档
- 已完成：重构个人账号引导、登录、Cookie/CSRF、锁定、会话上限、改密与登出；认证 DTO 进入 v1 Schema/OpenAPI；上传改为原始流前置限额、服务自有磁盘暂存和有界并发；冲突与未知项目不再发布 CAS 对象；就绪检查覆盖工件库；框架错误统一结构化；Task 创建恢复 API→`task.requested`→编排边界；并发取消只追加一次状态事件；API 内部拆分 Cookie、错误、事件和上传职责
- 测试与结果：`pnpm run check` 通过，147 个测试全部通过，总覆盖率 89.42%（MVP 门槛 80%）；Ruff、Pyright strict、TypeScript、`uv lock --check`、Compose 配置解析通过；API 镜像构建成功
- 问题：FastAPI TestClient 依赖链产生两条上游弃用警告，不影响运行和验收
- 阻碍点：无
- 决策：ADR-017 固化个人浏览器认证；ADR-018 固化任务接入/编排边界；按用户要求将 MVP 覆盖率门槛降至 80%，重型全量验收集中到里程碑、合并或发布前
- 下一步：认领 T08，基于 OpenAPI 搭建 Svelte 5 个人工作台并接入 T07 真实接口

### 2026-09-08：完成 T06 Worker 生命周期第二轮正确性修正

- 负责人：Codex（实现）/ Claude Code（收尾复核与合并）
- 状态：已完成
- 修改文件：`code/packages/worker/`、`code/packages/persistence/`（含迁移 `0005_job_retry_schedule`）、`code/packages/queue/`、`code/packages/contracts/`、`code/tests/worker/`、`code/tests/persistence/`、`code/docs/adr/015-job-leases-and-pending-recovery.md`、`code/docs/adr/016-worker-result-and-settlement-protocol.md`、`DEVELOPMENT_STATUS.md`
- 已完成：为租约引入唯一 fencing token 并在 complete/renew/release/fail_exhausted 全链路校验所有权，阻断心跳延迟造成的双执行；重试退避写入 `retry_not_before` 由 Worker 在同一消息循环内等待；`WAITING_PERMISSION` 不再 ACK、许可通过后可由 pending 恢复；领取循环在 fresh 与 PEL 间轮换、空扫描阻塞等待；心跳瞬态失败重试至租约截止；结算路径捕获 `JobLeaseConflict`/`PersistenceInvariantError` 并结构化记录；结果指纹对产物/证据 ID 排序；只读领取不再取行锁、移除死信脚本无效 `XPENDING`
- 测试与结果：修复遗留 Ruff B904 后 `pnpm run check` 全链路通过——135 个 pytest 通过、分支覆盖率 90.28%、Ruff 0 问题、Pyright 0 错误、TypeScript 通过、`uv lock --check` 通过
- 问题：无新增；Q-002、Q-003 保留
- 阻碍点：无
- 决策：补充 ADR-015、ADR-016 的 fencing token 与重试调度语义
- 下一步：认领 T07，创建 FastAPI 应用骨架并实现 Project、Artifact、Task 首批 API

### 2026-09-07：完成 T06 Code Review 可靠性修正

- 负责人：Codex
- 状态：已完成
- 修改文件：`code/packages/worker/`、`code/packages/persistence/`、`code/tests/worker/`、`code/tests/persistence/`、`code/docs/adr/015-job-leases-and-pending-recovery.md`、`code/docs/adr/016-worker-result-and-settlement-protocol.md`、`DEVELOPMENT_STATUS.md`
- 已完成：逐项确认五项 Review 意见；新增 `already_owned` 租约结果阻止同 owner 对活跃 Job 再次启动执行器；严格执行失败 kind 重试白名单；新增 `job_attempt_failures` 追加式审计迁移和幂等仓储；executor 与心跳同 tick 时优先消费执行结果；Worker 持续传递 `XAUTOCLAIM` 游标
- 测试与结果：重复执行和空白名单用例在旧实现上稳定失败，修复后通过；`pnpm run check` 全链路通过，127 个 pytest 测试、90.20% 分支覆盖率、Ruff 0 问题、Pyright 0 错误、TypeScript 通过；Dispatcher 镜像重建成功，`0004_job_attempt_failures` 迁移容器退出码 0且安全配置保持不变
- 问题：五项 Review 问题均已关闭；无新增问题
- 阻碍点：无
- 决策：补充 ADR-015、ADR-016，不改变控制面/执行面安全边界
- 下一步：认领 T07，基于现有仓储和工件登记服务实现 FastAPI 项目、工件与任务接口

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
| 2026-09-07 | T06 Code Review 回归 | 先运行重复执行与空重试白名单失败用例；再执行 `pnpm run check`、迁移漂移测试、`uv lock --check`、Compose 构建/迁移/安全配置检查 | 通过；127 个测试、90.20% 分支覆盖率；同 owner PEL 往返不重复执行，白名单、追加失败审计、心跳竞态和游标推进均有回归；`0004` 迁移退出码 0 | 具体工具副作用仍须遵守幂等接口；租约真实过期后的新 attempt 接管属于既定至少一次执行语义 |
| 2026-09-08 | T06 第二轮正确性修正 | 修复遗留 Ruff B904 后 `pnpm run check`（Ruff、Pyright strict、pytest `--cov --cov-fail-under=90`、TypeScript）与 `uv lock --check` | 通过；135 个测试、90.28% 分支覆盖率、Ruff 0 问题、Pyright 0 错误、TypeScript 通过、锁文件一致 | 未在远端 GitHub Actions runner 实跑，需由 PR 触发 |
| 2026-09-08 | T07 PR #5 审计修正与认证重构 | `pnpm run check`、`uv lock --check`、Compose 配置解析、`docker compose ... build api` | 通过；147 个测试、89.42% 分支覆盖率（MVP 门槛 80%）、Ruff/Pyright/TypeScript 通过，迁移与真实 PostgreSQL/Redis 集成通过，API 镜像构建成功 | 未推送远程分支，GitHub Actions 待推送后触发 |
| 2026-09-08 | T08 Svelte 工作台与容器交付 | `pnpm run check`、Web 生产构建、`uv lock --check`、Compose 配置解析与 Web 镜像构建 | 通过；147 个测试、89.45% 覆盖率；Svelte 检查 0 错误/0 警告；生产包与 `vulnweaver-web:dev` 镜像构建成功 | Playwright 真实浏览器 E2E 留待 T22 集中执行 |
| 2026-09-08 | T11 LangGraph 编排与检查点 | Dev Container `pnpm run check`；定向 PostgreSQL/Redis 编排、迁移和恢复测试；Dispatcher 迁移镜像；Orchestrator 镜像构建与用户检查 | 通过；171 个测试、87.53% 覆盖率；真实 task.requested 消费/ACK、中间节点恢复、Job/Outbox 幂等、策略拒绝/许可等待通过；数据库升级至 0007；镜像 UID 10001 | T12/T16 提供真实 ToolSpec 镜像摘要后再加入 Compose 常驻服务 |
| 2026-09-08 | T12 安全导入、源码索引与 Compose 链路 | Dev Container `pnpm run check`、`uv lock --check`；定向 Orchestrator/源码分析测试；Compose 配置、镜像构建、摘要比对、安全属性检查及隔离栈真实 HTTP 任务链路 | 通过；185 个测试、总覆盖率 86.55%；C/C++/Python/Java 索引和 ZIP/TAR 安全边界通过；真实 Job 成功并登记带父版本及精确工具镜像身份的派生索引工件 | Semgrep/cppcheck、PAIR、Finding 与 Task 最终聚合分别属于 T13-T15 |
| 2026-09-08 | T12 Review 正确性回归 | 定向源码分析/编排 PostgreSQL 测试；Dev Container `pnpm run check`、`uv lock --check`；重建并重启 orchestrator/analysis-worker；镜像摘要比对；真实 Compose 源码任务 | 通过；27 个定向测试、191 个全量测试、86.77% 覆盖率；慢解压/索引不阻塞事件循环，祖先路径冲突被拒绝，binary ToolSpec 无额外参数，真实 Import Job 成功并生成索引 | 未新增受控 CAS GC；沿用 ADR-012 的安全未引用对象保留语义 |
| 2026-09-08 | T14 PAIR 源码导入与查询 | T14/迁移/契约定向测试；Windows Selector 下全量 pytest；Ruff/Pyright/TypeScript；`uv lock --check`；Compose 配置解析、0009 迁移与 analysis-worker 镜像构建/启动 | 通过；14 个定向测试、198 个全量测试通过；迁移无 metadata drift；数据库 revision 为 `0009_pair_tables`；Worker 以 UID 10001 启动 | 未在远端 GitHub Actions runner 实跑；T15 Finding/Evidence 尚未实现 |
| 2026-09-08 | T13 静态工具与 Job 链路 | 变更文件 Ruff/Pyright；契约 TypeScript `tsc --noEmit`；契约、静态适配、调度、源码导入定向测试；Windows Selector 下全量 pytest；`uv lock --check`；Compose 配置解析与 `docker compose ... build analysis-worker`；容器内 Semgrep/cppcheck 样本扫描 | 通过；Ruff 全仓库、Pyright 变更文件、TypeScript 契约均无错误；30 个定向测试、196 个全量测试通过；镜像和真实工具扫描通过 | 未在远端 GitHub Actions runner 实跑；T14/T15 尚未覆盖 PAIR/Finding 消费 |
| 2026-09-08 | T01.2 CI 触发去重 | PyYAML BaseLoader 解析 `.github/workflows/quality-gate.yml` 并断言触发器集合；`git diff --check` | 通过；触发器仅为 `pull_request`、`workflow_dispatch`，无 `push` | 未在远端 GitHub Actions runner 实跑；平台必需检查和禁止直接推送仍需仓库配置保证 |
| 2026-09-09 | T15-R1 静态分析与 PAIR 审计修正 | 定向 PostgreSQL/静态工具测试；Dev Container `pnpm run check`；Compose config；analysis-worker 构建、网络检查及内外连通性探测 | 通过；33 个定向集成测试；全量 208 个测试、85.79% 覆盖率；Ruff/Pyright/TypeScript/Svelte 通过；Worker 可访问内部 PostgreSQL且外网不可达 | 远端 CI 尚未运行 |

## 10. 下一步

1. 继续 T15，将 `StaticAnalysisResult` 与 PAIR 函数/边引用接入候选 Finding/Evidence 生成。
2. 在编排层生成 ConfirmationContext 并调用 Review 门禁。
3. 实现独立复核上下文、证据快照和 Task 聚合状态更新。

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
