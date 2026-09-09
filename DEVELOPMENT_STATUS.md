# Agent 动态交接台账

> 本文件只维护当前进度、问题、阻碍、决策摘要、验证结果和下一步。稳定开发规则见 `AGENTS.md`；架构依据为 `系统架构设计与技术选型.md`，实现任务依据为 `系统实现模块拆分.md`。开始工作前必须阅读 `AGENTS.md` 和本文件，结束或交接前必须更新本文件。

## 1. 项目目标

构建一个面向已授权源码仓库和 x86/x64 ELF/PE 二进制的软件漏洞挖掘系统。系统通过智能体编排静态分析、逆向分析、模糊测试、独立复核、最小复现和可选利用验证，并输出可追溯的 Finding、证据链与报告。

## 2. 当前工程状态

- **项目名称**：VulnWeaver（漏洞织鉴）
- **当前阶段**：P2 源码静态分析 MVP 待端到端验收；P3 二进制分析 MVP 已启动，T16 进行中
- **总体状态**：T15 已完成；P2 仅缺真实 REVIEW 模型四语言端到端验收。T16-R1 已形成可验证检查点：新增版本化二进制分析契约与独立包，安全识别 x86/x64 ELF/PE，受控接入 DIE/UPX/objdump/Ghidra Headless/angr，保存规范化函数、指令、导入与字符串；UPX 原件/脱壳件保持父子谱系，Ghidra 等工具失败时保留已有结果并标记 `partial`。
- **最后更新**：2026-09-09（Asia/Shanghai）
- **代码目录**：`code/` 已初始化 Python/TypeScript 工作区、Dev Container 与 Compose 基础设施
- **版本管理**：远端 `origin` 指向 `https://github.com/NTFago/VulnWeaver.git`；当前 `feat/t16-binary-analysis` 基于 `feat/t15-completion@80ad20a`，T16-R1 已完成本地验证，尚未推送或合并。
- **稳定开发规则**：根目录 `AGENTS.md` 已建立
- **当前负责人**：Codex；已认领 T16 二进制导入与逆向适配任务包

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
| T15 Finding、Evidence 与复核 | 已完成 | Codex | 完成 Evidence/Finding/Review/Annotation 持久化、静态候选去重投影、强证据确认门禁、有界源码事实、结构化独立复核、不可变结论工件、自动复核 Job、Task 终态聚合及个人控制面查询/修正 API | 无；真实模型与四语言完整流程归 P2 环境验收 | 2026-09-09 |
| T16 DIE/UPX/Ghidra/angr 适配 | 进行中 | Codex | T16-R1 已交付 `BinaryAnalysisResult` 契约、独立 `binary-analysis` 包、ELF/PE 头与节区安全解析、字符串/函数/指令/导入规范化、固定参数无 Shell 的 DIE/UPX/objdump/Ghidra/angr 适配、UPX 派生谱系、部分失败结果和 Worker/ToolSpec/Compose 接入 | 补齐 Ghidra 伪代码/Xref/CFG 与 angr 定点符号分析的真实工具镜像验收；Docker Hub 基础镜像解析暂失败，镜像摘要与 Compose 全链路待网络恢复后验证；随后进入 T17 | 2026-09-09 |
| T15-R1 静态分析与 PAIR 审计修正 | 已完成 | Codex | PAIR 调用边按关系身份聚合调用点并消除名称碰撞误连；Review 串行锁定并按不可变历史重建状态；规范化事实时间戳；导入/静态持久化异常返回终态；修正静态谱系、输出上限、严重度和 Worker 外网隔离 | 无 | 2026-09-09 |
| T15-R2 结构化模型独立复核 | 已完成 | Codex | review 档位结构化调用；AgentRun/Review/ReviewConclusion Evidence 原子登记；固定身份与来源、弱证据降为 unverifiable、事实过期/取消/非法迁移拦截；并发单次结算、失败回放、数据库回滚后重试；91 个定向测试及静态/契约检查通过 | 无（本包仅为显式复核应用服务）；自动调度、有界源码事实读取、Task 聚合及 Annotation 仍归 T15 后续 | 2026-09-09 |
| T15-R3 有界源码复核事实 | 已完成 | Codex | 复用安全导入器；校验任务输入/项目归属、归档与文件摘要；限制归档/解压/文件/文本大小和行数；源码片段经网关脱敏并进入不可变复核快照；缺失或截断时禁止确认/判误报；全量 246 测试通过 | 本包无剩余；自动调度、完整调用邻域、Task 聚合和 Annotation 仍属后续任务；未进行镜像或真实模型验收 | 2026-09-09 |
| T15 R2/R3 Git 历史整合 | 已完成 | Codex | 核对快照基线与 `origin/main` 文件树一致，从 `origin/main@e9f7914` 创建正常历史分支并无冲突移植 3 个提交；Docker 全量门禁、锁文件、Compose 配置及受影响镜像构建均通过，本地 `main` 快进到整合结果 | 无；远端 `main` 尚未推送 | 2026-09-09 |
| T15-R4 自动复核、Task 聚合与 Annotation/API | 已完成 | Codex | 最后一个静态 Job 终止时同事务为去重 Findings 创建 REVIEW Job/Outbox；执行器传递稳定 attempt 身份和 `max_model_tokens`；Worker 结算 hook 聚合 Task 并追加事件；0014 新增追加式 Annotation；补齐 Finding/Evidence、PAIR、AgentRun、Annotation 与人工 Review API | 无 | 2026-09-09 |

状态只允许使用：`未开始`、`进行中`、`受阻`、`待验证`、`已完成`、`已取消`。

## 4. 当前问题

| ID | 问题 | 影响 | 临时处理 | 状态 | 负责人 |
|---|---|---|---|---|---|
| Q-002 | 首版开发环境是否必须同时支持 Windows Worker 未明确 | 影响 P4 的本机验收范围 | 先冻结跨平台消息协议，Windows 执行节点在 Linux MVP 后实现 | 待处理 | 未分配 |
| Q-003 | Windows Python 3.12 在含中文的工作区路径中以 GBK 读取 uv editable `.pth`，会导致启动失败 | 影响 Windows 宿主直接使用默认 editable workspace；Dev Container/Linux 不受影响 | Windows 本机使用 `uv sync --no-editable`，验证命令使用 `uv run --no-sync`；等待 Python/uv 上游兼容或迁移到纯 ASCII 路径 | 待处理 | 未分配 |
| Q-004 | 现有 Evidence 仓储测试与 Finding 测试共用固定 input_ref，先运行 Finding 再运行 Evidence 时出现顺序依赖 | 非标准目录顺序下 1 个原有断言失败，不是本轮复核行为回归 | 按正常目录顺序 91 个测试全通过；后续将原有测试数据改为独立命名空间，不放宽断言 | 待处理 | 未分配 |
| Q-005 | 复核源码事实使用位置附近有界片段和 PAIR 关系快照，尚未拼接跨函数调用点的完整源码邻域 | 复杂跨函数问题的模型召回率可能受影响，但缺失/截断门禁仍阻止弱事实被确认，不影响 T15 安全验收 | 自动复核的租约、预算、Outbox 和并发去重已完成；后续按真实 P2 样本评估是否扩展调用邻域 | 待处理 | 未分配 |
| Q-006 | T16 analysis-worker 镜像重建时 Docker Desktop 无法访问 `registry-1.docker.io` 获取 `python:3.12-slim` 元数据 | 不影响 Dev Container 内代码、契约、真实 PostgreSQL 与本机 binutils 验证，但阻止本轮更新镜像摘要和执行 Compose 二进制任务 E2E | 保留既有国内 Python/Debian 镜像配置；已确认失败发生在基础镜像元数据解析，未切换未经项目确认的镜像源 | 待处理 | Codex |

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

### 2026-09-09 12:26：完成 T16-R1 ELF/PE 安全导入与规范化逆向检查点

- 负责人：Codex
- 状态：进行中（T16-R1 检查点完成，T16 仍需真实 Ghidra/angr 与镜像验收）
- 修改文件：`code/packages/binary-analysis/`、`code/packages/contracts/`、`code/packages/source-analysis/`、`code/apps/analysis-worker/`、`code/deploy/tool-specs/binary-import.json`、`code/deploy/ghidra/ExportVulnWeaver.java`、`code/compose.yaml`、工作区依赖/锁文件及 `code/tests/binary_analysis/`
- 已完成：新增 `BinaryAnalysisResult` 及 ELF/PE、节区、函数、指令、字符串、导入、工具运行契约；纯解析器仅接受 x86/x64 ELF/PE 并校验表/节区边界和输入大小；外部工具统一使用固定参数、无 Shell、取消/超时/合并输出上限；实现 DIE、UPX、objdump、Ghidra Headless、angr CFGFast 适配及有界导出脚本；二进制 Job 校验 Task/Project/Artifact 归属，结果和 UPX 脱壳件以确定性 ID 登记为不可变派生工件，重放保持幂等；Ghidra 等已配置工具失败时保留基础结果并将分析标记为 `partial`。
- 测试与结果：Dev Container 全量 `pnpm run check` 通过，266 passed、总分支覆盖率 83.25%，Ruff/Pyright/TypeScript/Svelte 均通过；T16 定向 15 passed，包含真实 PostgreSQL 派生谱系/幂等、恶意边界、输出洪泛终止、取消、固定参数及部分失败；`uv lock --check` 与 Compose 配置通过；真实 `/bin/ls` ELF 由 objdump 取得 117 个函数、21915 条指令和 2 个依赖，构造 PE 取得 1 个函数和 5 条指令。
- 问题：`docker compose build analysis-worker` 在解析 Docker Hub `python:3.12-slim` 元数据时网络失败，故未生成新镜像摘要；DIE/UPX/Ghidra/angr 尚未在最终镜像中进行真实工具链运行。
- 阻碍点：无；镜像网络问题记录为 Q-006，不阻止继续实现 Ghidra/angr 规范化和 T17 契约。
- 决策：无新增 ADR；继续遵循 M10、ADR-012/015/016/019，二进制样本不在宿主机执行，外部分析器只处理服务自有 scratch 副本。
- 下一步：扩展 T16 结果以保存 Ghidra 伪代码、Xref/CFG 和 angr 定点分析事实，并在基础镜像可解析后重建 analysis-worker、回填精确 ToolSpec 镜像摘要并跑 ELF/PE Compose E2E。

### 2026-09-09 11:05：完成 T15-R4 自动复核、Task 聚合与 Annotation/API

- 负责人：Codex
- 状态：已完成
- 修改文件：`code/packages/orchestrator/`、`code/packages/worker/`、`code/packages/model-gateway/`、`code/packages/persistence/`、`code/packages/source-analysis/`、`code/apps/analysis-worker/`、`code/apps/api/`、Compose/环境示例、锁文件及对应测试
- 已完成：所有静态分析 Job 终止后，在 Worker 终态结算事务中为当前去重 Finding 创建唯一 REVIEW Job 与 Outbox，避免复核早于并行工具证据；模型调用受租约 attempt 与 Task `max_model_tokens` 约束，未配置模型形成可见结构化失败；Task 从 Job/Finding 事实聚合并按合法阶段追加事件；新增 `0014_annotations` 迁移、追加式函数/Finding 标注、人工复核和 Finding/Evidence/PAIR/AgentRun 查询 API。
- 测试与结果：Dev Container 全量 `pnpm run check` 为 250 passed、覆盖率 85.79%，Ruff/Pyright/TypeScript/Svelte 全通过；定向复核/聚合/API/迁移/Worker 测试 52 passed；`uv lock --check` 与 Compose 配置通过；API、analysis-worker、migrate 镜像构建成功；开发数据库升级到 `0014_annotations`，API `/health/ready` 返回 ready，analysis-worker 非 root、只读根文件系统且无 Docker Socket。
- 问题：首次全量运行未传容器内 PostgreSQL/Redis 地址，109 个集成测试被跳过并导致覆盖率不足；用正确服务地址重跑后全部通过。新增 API 样本最初与既有 Evidence 固定输入引用碰撞，改为独立测试引用后全量通过。仅保留既有 Starlette/AnyIO 弃用警告和 analysis-worker 未被覆盖率导入警告。
- 阻碍点：无。
- 决策：无新增 ADR；沿用 ADR-013/015/016/019 的 Outbox、租约、结算和恢复语义，Annotation 为既定 M15 追加历史。
- 下一步：配置一个 analysis-plane 可达的 OpenAI 兼容复核模型，用 C/C++/Python/Java 无害样本执行 P2 端到端验收；随后认领 T16。

### 2026-09-09 10:02：完成 T15 R2/R3 Git 历史整合

- 负责人：Codex
- 状态：已完成
- 修改文件：Git 历史、`DEVELOPMENT_STATUS.md`、`code/docs/progress/2026-09-09-supplied-snapshot-history.md`
- 已完成：确认无祖先分支的根快照 `fe91646` 与 `origin/main@e9f7914` 文件树完全一致；保留原始 `feat/t15-review-model`，从 `origin/main` 创建 `feat/t15-review-model-main` 并无冲突移植 R2/R3 的 3 个提交；修正快照专属交接描述并将本地 `main` 快进到整合结果。
- 测试与结果：Docker Dev Container 内使用服务网络地址运行 `pnpm run check`，246 tests passed、总覆盖率 86.68%，Ruff/Pyright/TypeScript/Svelte 全通过；`uv lock --check` 与 Compose 配置检查通过；`orchestrator`、`analysis-worker` 镜像构建成功。首次容器测试沿用宿主机端口导致 106 个集成测试跳过及覆盖率不足，修正测试连接变量后已全量重跑通过。
- 问题：仅有既有 Starlette/AnyIO 弃用警告和 analysis-worker 覆盖率未导入警告，不影响门禁。
- 阻碍点：无。
- 决策：采用从 `origin/main` 移植提交的方式恢复正常祖先历史，不使用 `--allow-unrelated-histories` 制造 add/add 冲突；无新增 ADR。
- 下一步：接入复核 Job 的租约、预算与 Outbox，再实现 Task 聚合及 Annotation/API。

### 2026-09-09 03:25：保存 T15-R3 源码复核事实检查点

- 负责人：Codex；状态：已完成（仅 R3；T15/P2 整体未完成）
- 产物：`source-analysis/excerpts.py`、`orchestrator/source_facts.py`、模型复核接入、对应无害测试；增加现有内部包依赖，第三方版本未变。
- 安全边界：只读任务已登记且属于同一项目的源码归档；复用安全解压，禁路径穿越/符号链接；同一份有界字节完成摘要校验与读取；不执行任何样本；源码经网关脱敏，审计快照保留来源摘要和实际片段。
- 验证：Windows Selector 下全量 `pytest -q -p no:cacheprovider --tb=short --cov --cov-report=term --cov-fail-under=80`，246 passed，覆盖率 86.64%；Ruff/Pyright 通过。首次全量仅新增脱敏测试错误地预期 `[REDACTED]`，已按既有实现修正为 `<redacted>`，保留原文不得外发断言后全量重跑通过。
- 未覆盖：analysis-worker 进程入口未被覆盖率导入；存在既有 Starlette/AnyIO 弃用警告；未运行镜像、完整浏览器 E2E 或真实模型调用。
- 交接：用户已确认 origin 地址，功能检查点 `9c392e7` 已成功推送至 `origin/feat/t15-review-model` 并建立上游跟踪；没有合并或强推。原快照独立 Git 历史与远端历史的整合留待单独评估。
- 下一步：为复核服务接入 Job 租约、预算与 Outbox；补 Task 聚合及 Annotation/API；源码片段之外的函数调用邻域按需扩展。

### 2026-09-09 02:33：完成 T15-R2 结构化模型独立复核检查点

- 负责人：Codex；状态：已完成（T15 整体仍进行中）
- 接手来源：仅本次指定 `VulnWeaver-main(1)/VulnWeaver-main`。原目录无 Git 元数据，原快照提交 `fe91646`，新分支 `feat/t15-review-model`；未读取旧工作区进度、未设置远端或推送。
- 产物：`model_reviews.py`、复核门禁事务复用、Task 可选锁定读取、13 个模型复核测试实例、中文模块说明；只增加现有内部工件库依赖，第三方锁定版本未改变。
- 行为：隔离事实调用 review 档位；服务固定身份/模型/时间；强证据门禁拒绝时保存不可验证状态并保留原提议；结论仅 contextual；AgentRun/Review/Evidence 原子登记。覆盖成功重放、并发、超时/非法输出、工件故障、事务回滚重试、事实过期、取消和非法状态迁移。
- 验证：Windows Selector 下 91 个定向测试通过（真实 PostgreSQL 临时库、契约、迁移无漂移）；Ruff 全仓库、Pyright strict、TypeScript/Svelte 检查与 `uv lock --check` 通过。
- 环境记录：默认 Windows Proactor 不兼容 psycopg，改用进程内 Selector；沙箱对 uv 缓存、pytest 临时目录及 npm 网络的拒绝经授权重试解决。安装始终使用项目国内镜像，未切源。自定义测试顺序暴露原有 Q-004，未修改或弱化断言。
- 未执行：全量覆盖率、完整 E2E、服务镜像和真实模型验收；本轮不改部署/公共 Schema，未操作主业务库或运行样本。原快照的历史验收不当作本轮验证。
- 下一步：将显式复核服务接入已成功静态 Job 的租约调度，再实现 Task 聚合、Annotation 与查询接口。历史记录超出 10 条的部分已归档，未使用旧交接。

### 2026-09-09 01:21：完成 T15 静态候选投影与独立复核确认门禁

- 负责人：Codex
- 状态：进行中
- 修改文件：`code/packages/source-analysis/`、`code/packages/orchestrator/`、`code/packages/persistence/`、`code/tests/source_analysis/`、`code/tests/orchestrator/`、`code/tests/finding/`、`DEVELOPMENT_STATUS.md`
- 已完成：静态诊断按任务、CWE 与精确位置生成稳定候选身份；同一 Job 重放幂等，Semgrep/cppcheck 同位置候选合并并提升严重度；每条诊断登记 supporting Evidence，保存结果工件摘要、固定命令摘要与 PAIR 邻域快照；FindingEvidence 列表与 Finding 聚合 ID 同步；新增隔离复核事实包，过滤模型解释和自由叙述，并在事务锁内调用领域确认策略后写入 Review；修正 `contextual` 关系数据库约束
- 测试与结果：Dev Container `pnpm run check` 通过，209 个测试全部通过、总覆盖率 86.10%，Ruff/Pyright/TypeScript/Svelte 均通过；`uv lock --check`、Compose 配置、`0013` 迁移、analysis-worker/dispatcher 镜像构建通过；开发库 revision 为 `0013_finding_evidence_contextual`
- 问题：本机 uv 仍受 Q-003 影响，本轮依既定方案在 Dev Container 验证；无新增问题
- 阻碍点：无
- 决策：无新增重大架构决策；沿用证据驱动确认与上下文隔离约束
- 下一步：在 orchestrator 使用 review 模型档位消费 `ReviewFactContext` 的结构化事实，保存 AgentRun/ReviewConclusion Evidence，并聚合 Task 状态。

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

较早记录见 `code/docs/progress/2026-09-09-supplied-snapshot-history.md`，仅来自本次指定快照。

## 9. 验证记录

| 日期 | 任务 | 命令/方式 | 结果 | 未覆盖范围 |
|---|---|---|---|---|
| 2026-09-09 | T16-R1 ELF/PE 安全导入与规范化逆向 | Dev Container `pnpm run check`；T16 定向测试；契约生成与 `uv lock --check`；Compose 配置；真实 `/bin/ls` ELF 与构造 PE objdump 探测；analysis-worker 镜像构建尝试 | 266 passed、83.25% 覆盖率；静态和前端检查全通过；T16 15 passed；ELF/PE 均取得规范化函数/指令；UPX 父子谱系与重放幂等通过 | Docker Hub 基础镜像元数据解析失败，未重建 analysis-worker 或执行 Compose 二进制 Job；真实 DIE/UPX/Ghidra/angr 工具链待补 |
| 2026-09-09 | T15-R4 自动复核、聚合与 Annotation/API | Dev Container 内以 Compose 服务地址运行 `pnpm run check`；定向复核/聚合/API/迁移/Worker 测试；`uv lock --check`；Compose 配置；构建 API/analysis-worker/migrate；实际迁移、ready 与容器安全属性检查 | 250 passed，覆盖率 85.79%；所有静态和前端检查通过；定向 52 passed；数据库 revision `0014_annotations`；API ready，服务镜像启动成功 | 未配置真实复核模型，未跑四语言完整 P2 E2E；首次无效全量运行因容器地址错误跳过 109 项，已纠正重跑 |
| 2026-09-09 | T15 R2/R3 Git 历史整合 | Dev Container 内设置 `VULNWEAVER_TEST_ADMIN_DATABASE_URL`/`VULNWEAVER_TEST_REDIS_URL` 为 Compose 服务地址后运行 `pnpm run check`；`uv lock --check`；Compose `config --quiet`；构建 `orchestrator`、`analysis-worker` | 246 passed，覆盖率 86.68%；Ruff/Pyright/TypeScript/Svelte 无错误；锁文件、Compose 配置及两个受影响镜像构建通过 | 未运行完整浏览器 E2E 或真实模型调用；远端 CI 尚未运行 |
| 2026-09-09 | T15-R3 全量回归 | Windows Selector 启动 pytest，参数 `-q -p no:cacheprovider --tb=short --cov --cov-report=term --cov-fail-under=80`；`.venv/Scripts/ruff.exe check .`；`pnpm exec pyright` | 246 passed，86.64%；Ruff/Pyright 无错误；真实临时 PostgreSQL/Redis 与契约测试通过 | 未验证服务镜像、完整 E2E 和真实模型；analysis-worker 入口未被覆盖率导入 |
| 2026-09-09 | T15-R2 当前快照验收 | `.venv/Scripts/python.exe -c "import asyncio, pytest; asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy()); raise SystemExit(pytest.main(['tests/contracts','tests/domain','tests/evidence','tests/finding','tests/model_gateway','tests/orchestrator','tests/persistence/test_repositories.py','tests/persistence/test_migrations.py','-q','-p','no:cacheprovider','--tb=short']))"`；`.venv/Scripts/ruff.exe check .`；`pnpm exec pyright`；`pnpm run check:typescript`；`uv lock --check` | 91 passed；Ruff 无问题，Pyright 0 错误，Svelte 0 错误/警告，契约与锁文件一致 | 未执行全量覆盖率、镜像、E2E 或真实模型调用；先 Finding 后 Evidence 的非标准顺序触发原有 Q-004 |
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
| 2026-09-09 | T15 静态候选投影与独立复核门禁 | 定向 Finding/Orchestrator/迁移测试；Dev Container `pnpm run check`；`uv lock --check`；Compose 配置、迁移与镜像构建 | 通过；209 个全量测试、86.10% 覆盖率；Ruff/Pyright/TypeScript/Svelte 通过；`0013` 升降级、跨工具去重、重放幂等、PAIR 快照和强证据确认门禁通过 | review 模型实际调用、ReviewConclusion Evidence、Task 聚合与远端 CI 尚未执行 |

## 10. 下一步

1. 继续 T16：在现有有界 Ghidra/angr 适配上补充伪代码、Xref、CFG 和定点符号分析的版本化结果；真实工具不可用时继续保留结构化 `unavailable/failed` 与已有部分产物。
2. Docker 基础镜像可解析后重建 analysis-worker，更新全部同镜像 ToolSpec 的精确摘要，并以无害 x86/x64 ELF/PE（含 UPX 固定样本）执行 Compose Job、父子工件和 `partial` 端到端验收。
3. 为 analysis-worker 配置一个 `analysis-plane` 可达的 OpenAI 兼容 REVIEW 模型，补跑 C/C++/Python/Java P2 端到端验收；随后认领 T17，将 T16 二进制结果导入 PAIR 地址模型。

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
