# 当前交付快照的历史记录归档

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

本文件仅归档本次用户指定目录内原有台账的较早记录；未经本轮重新验证，不作为当前运行状态。未使用旧工作区的交接内容。

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
