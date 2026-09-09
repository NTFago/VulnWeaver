# Agent 动态交接台账

> 本文件只维护当前进度、问题、阻碍、决策摘要、验证结果和下一步。稳定开发规则见 `AGENTS.md`；架构依据为 `系统架构设计与技术选型.md`，实现任务依据为 `系统实现模块拆分.md`。

## 1. 项目目标

构建面向已授权源码仓库和 x86/x64 ELF/PE 二进制的软件漏洞挖掘系统。系统通过智能体编排静态分析、逆向分析、模糊测试、独立复核、最小复现和可选利用验证，输出可追溯的 Finding、证据链和报告。

## 2. 当前工程状态

- **项目名称**：VulnWeaver（漏洞织鉴）
- **当前日期**：2026-09-10（Asia/Shanghai）
- **当前阶段**：P2 源码静态分析代码已完成，待真实 REVIEW 模型四语言端到端验收；P3 二进制分析和 Sandbox Runner 处于工具镜像/动态验收阶段；P4 Proof/Exploit 已完成主要代码接入，待 Runner HTTP 端到端回放；P5 报告、全链路 UI 和 E2E 正在收口。
- **当前分支**：`feat/web-onboarding-settings`（独立 worktree，未推送）；正在重构首次 Web 注册、产品设置与开箱部署流程。
- **当前负责人**：Codex。T23 已在独立 worktree 完成；主线仍优先处理 T20/T21/T22 的真实回放与最终验收。
- **最近一次全量门禁**：Dev Container 内 `pnpm run check` 通过；322 个测试通过、1 个跳过（Docker runtime 集成为 opt-in），分支覆盖率 81.22%；PostgreSQL/Redis 集成测试通过 `VULNWEAVER_TEST_ADMIN_DATABASE_URL` 和 `VULNWEAVER_TEST_REDIS_URL` 指向 compose 服务名后完整执行。Ruff、Pyright、TypeScript 和 Svelte 检查通过。
- **安全边界**：控制面不挂载 Docker Socket；动态样本、模糊测试和 Proof/Exploit 只能经独立 Sandbox Runner，以固定 ToolSpec、禁网、非 root、只读输入、资源预算和输出配额执行。

## 3. 开发进度

| 模块/任务包 | 状态 | 负责人 | 当前完成内容 | 剩余工作 | 最后更新 |
|---|---|---|---|---|---|
| 架构设计 | 已完成 | 用户/设计阶段 | 系统目标、架构、安全、数据与技术选型已确定 | 实现中持续校验 | 2026-09-07 |
| 实现模块拆分 | 已完成 | Agent | M01-M17、P0-P5、T01-T22 已拆分 | 随实现维护依赖变化 | 2026-09-07 |
| T01 工程工作区 | 已完成 | Codex | uv、pnpm、质量工具、Dev Container、PostgreSQL/Redis Compose 和国内依赖源已配置 | 无 | 2026-09-07 |
| T02 公共契约 | 已完成 | Codex | v1.0.0 JSON Schema、Python/TypeScript 类型、状态迁移、聚合、确认策略和幂等规则已实现 | 无 | 2026-09-07 |
| T03 PostgreSQL 迁移与仓储 | 已完成 | Codex | 核心实体迁移、仓储、枚举序列化和 PostgreSQL 回归验证已完成 | 后续任务按职责追加业务表 | 2026-09-07 |
| T04 本地内容寻址工件库 | 已完成 | Codex | SHA-256 CAS、派生谱系、不可覆盖、原子发布和 fsync 语义已实现 | 受控 GC、MinIO 后端留待后续部署 | 2026-09-07 |
| T05 Redis Streams 与 Outbox Dispatcher | 已完成 | Codex | 至少一次投递、退避、结构化读取、事件一致性和并发保护已实现 | 无 | 2026-09-07 |
| T06 Worker 租约与幂等框架 | 已完成 | Codex | fencing token、租约接管、重试、心跳、结果结算、ACK/死信和恢复语义已完成 | 无 | 2026-09-08 |
| T07 FastAPI 首批控制面 API | 已完成 | Codex | 个人认证、流式上传、任务投递/取消、统一错误、就绪检查和 OpenAPI 已完成 | 无 | 2026-09-08 |
| T08 Svelte 项目与任务页面 | 已完成 | Codex | 登录、项目、上传、任务、Job 和 WebSocket 事件恢复已完成 | 完整 Finding/报告/可观测工作台归 T22 | 2026-09-08 |
| T09 ToolSpec 与 Policy Engine | 已完成 | Codex | Tool Registry、ActionPlan 校验、策略拒绝/许可等待、资源边界和审计记录已完成 | 无 | 2026-09-08 |
| T10 模型访问适配与运行记录 | 已完成 | Codex | OpenAI 兼容接入、模型路由、超时重试、限流、结构化输出和 AgentRun 记录已完成 | 无 | 2026-09-08 |
| T11 LangGraph 主流程与检查点 | 已完成 | Codex | `task.requested` 消费、管线选择、Policy 门禁、Job/Outbox 幂等登记和检查点恢复已完成 | 无 | 2026-09-08 |
| T12 安全导入与 tree-sitter 索引 | 已完成 | Codex | 安全导入、索引、SourceImportExecutor、ToolSpec 和 Worker/Compose 链路已完成 | 无；后续工具验收另计 | 2026-09-08 |
| T13 Semgrep/cppcheck 适配 | 已完成 | Codex | 固定参数无 Shell 适配、静态结果契约、派生工件和静态 Job 已完成 | 无 | 2026-09-08 |
| T14 PAIR 源码导入与查询 | 已完成 | Codex | PAIR 契约、关系表、幂等仓储、函数/位置/调用邻域查询已完成 | 无 | 2026-09-08 |
| T15 Finding、Evidence 与复核 | 已完成 | Codex | Finding/Evidence/Review/Annotation、候选投影、强证据门禁、独立复核、Task 聚合和控制面查询已完成 | 真实模型四语言流程归环境验收 | 2026-09-09 |
| T16 DIE/UPX/Ghidra/angr 适配 | 待验证 | Codex | ELF/PE 解析、函数/指令/CFG/Xref/伪代码/符号事实、UPX 父子工件和 Worker 接入已完成；analysis-worker 已加入 UPX 并回填 ToolSpec 摘要 | 真实 DIE/Ghidra/angr 与 Compose 二进制 E2E；angr 为可选能力 | 2026-09-09 |
| T17 PAIR 二进制导入与查询 | 已完成 | Codex | 二进制函数/基本块/指令/Xref 导入、地址查询、Worker 和 API 接入已完成 | 最终 Docker 二进制 E2E 随 T16 验收 | 2026-09-09 |
| T18 Sandbox Runner 安全基线 | 待验证 | Codex | Sandbox 契约、无 Shell Docker runtime、隔离输出、禁网、非 root、资源限制、超时取消、CAS 输出、HTTP 服务和独立镜像已完成 | 配置真实工具摘要并完成独立 Runner 动态验收 | 2026-09-09 |
| T19 AFL++/CASR 与崩溃分诊 | 进行中 | Codex | Fuzz/Crash 契约、预算门禁、清单解析、稳定聚类、CAS 编排和固定 ToolSpec/profile 已完成 | 固定 AFL++/CASR 镜像下完成无害样本、预算、覆盖率和 crash cluster 验收 | 2026-09-09 |
| T19-R2 AFL++/CASR Sandbox 集成 | 待验证 | Codex | 目标/种子 CAS bundle、单次 Runner 调用、summary/manifest/minimized-input 解析和回归测试已完成 | 真实 AFL++/CASR 镜像回放；不得在宿主执行样本 | 2026-09-09 |
| T20 Proof/Exploit 流程 | 进行中 | Codex | ProofRequest、Poc 持久化、Scheduler/Worker/API、Finding Proof Job 发起接口、SandboxRunnerClient、固定 Proof/Exploit profile 和无害容器回放已完成 | 通过 HTTP Runner 提交带 CAS 工件的 Proof/Exploit 请求，并验收策略拒绝、重放和部分失败 | 2026-09-09 |
| T21 Markdown/PDF/SARIF 报告 | 进行中 | Codex | 报告生成、派生工件登记、Job/Worker 路由、版本化内容读取、Job 结果查询、PDF 生成和 Web 下载入口已完成 | 真实数据库 Finding 报告回放及完整 SARIF/PDF/浏览器验收 | 2026-09-09 |
| T22 全链路 UI、可观测性与 E2E | 进行中 | Codex | 任务页 Finding 摘要/详情、证据链与复现记录查询、Markdown/SARIF/PDF 报告操作和下载入口已接入 | 浏览器自动化全链路、可观测性收口和最终验收报告 | 2026-09-09 |
| T23 Web 首次注册与产品设置 | 已完成 | Codex（独立 worktree） | Web 一次性管理员注册、事务竞争裁决、认证/CSRF 设置 API、模型 URL/名称/API Key/重试参数设置页、API Key 写后不回显/显式清除、Worker DB 配置读取、迁移、Compose 与升级文档已完成 | 合并后在独立 TLS 部署完成真实浏览器首次启动验收；API Key 按用户选择明文落库，数据库/备份读取者可见 | 2026-09-10 |

## 4. 当前问题

| ID | 问题 | 影响 | 当前处理 | 状态 | 负责人 |
|---|---|---|---|---|---|
| Q-003 | Windows Python 3.12 在含中文路径的工作区中读取 uv editable `.pth` 可能失败 | Windows 宿主直接使用 editable workspace 不稳定 | Windows 使用 `uv sync --no-editable`，项目门禁统一在 Dev Container/Linux 执行 | 待处理 | 未分配 |
| Q-005 | 复核源码事实目前主要是位置附近的有界片段和 PAIR 关系快照，尚未自动扩展跨函数调用邻域 | 复杂跨函数问题的模型召回率可能受影响；安全门禁仍会阻止弱事实确认 | 先以真实 P2 样本评估，必要时再扩展事实读取范围 | 待处理 | 未分配 |
| Q-006 | Proof/Exploit 创建接口未校验客户端传入的 `script_ref` 是否归属当前 Finding 的 task 项目 | 用户可传入其他项目共享 CAS 存储中的派生对象引用，沙箱仅校验引用存在性，可能越出 Finding 项目范围执行脚本 | 需在 API/策略层增加 script_ref 与 task 项目归属校验，先设计从原始 CAS 引用推导项目归属的方案 | 待处理 | 未分配 |
| Q-007 | ProofJobExecutor 的数据库事务横跨长时间沙箱 HTTP 调用 | 沙箱运行期间（默认最长 120s）持续占用一条 DB 连接，并发下可能耗尽连接池阻塞其他 DB 工作 | 拆分事务（沙箱调用前后分段），需评估对原子性和 TOCTOU 语义的影响；当前 concurrency=1 影响有限 | 待处理 | 未分配 |

## 5. 当前阻碍点

当前无阻碍。T16/T18/T19/T20/T21/T22 的未完成项属于待验证工作，不应标记为阻碍。

## 6. 待确认事项

当前无待确认事项。已确认决策和完整 ADR 文件见 `code/docs/adr/`。

## 7. 当前相关技术决策

| ADR | 当前决策 |
|---|---|
| ADR-006 | 动态执行只能由独立 Sandbox Runner 负责，控制面和普通 Worker 不挂载 Docker Socket。 |
| ADR-008 | Python 使用 uv、TypeScript 使用 pnpm，依赖安装使用项目配置的国内镜像。 |
| ADR-014 | CI 使用 Ruff、Pyright、pytest 和前端检查；PR/手动触发，`main` 通过分支保护复用检查结果。 |
| ADR-015/016 | PostgreSQL Job 租约是执行权事实来源；WorkerResult 先落库，再按结果结算 ACK、重试或死信。 |
| ADR-018/019 | API 只登记任务请求；编排层负责初始 Job/Outbox、检查点、幂等重放和恢复。 |
| ADR-020 | 静态工具失败保留结果工件并结构化结算失败；Task 阶段由实际 Job 推导。 |
| ADR-021 | 空库通过 Web 一次性注册；模型连接与 API Key 由前端管理并持久化，API Key 不回显且传输依赖 HTTPS；基础设施与安全上限仍由部署配置注入。 |

## 8. 最近完成记录

| 日期 | 任务/变更 | 验证结果 | 后续工作 |
|---|---|---|---|
| 2026-09-10 | T23 Web 首次注册与产品设置 | 独立网络与 tmpfs PostgreSQL 中 API/迁移/契约 34 passed；Ruff、Pyright、Svelte、Vite build、Compose config 通过；未触碰既有 VulnWeaver 容器/网络/卷 | 合并后在独立 TLS 部署完成浏览器首次启动 E2E |
| 2026-09-09 | AGENTS.md 课设支撑性修订 | 对照课设功能要求审查开发规则：新增功能验收锚点、Dev Container 门禁约定、静态解析与运行样本边界澄清、教学漏洞样本规则、提示词资产管理和分支合并后清理规则；修正根目录文件清单与过期分支记录；已清理 7 个已合并本地功能分支和远程旧分支；纯文档修订，无代码行为变化 | 合并 PR #16 后继续按 T20/T21/T22 验收事项推进 |
| 2026-09-09 | PR 前质量检查修复（`4318939`） | Pyright 定位可观测性端点 9 处类型错误，修复 `list_after` 位置传参运行时 Bug、failure 窄化和 `_count_values` 类型，并新增带失败 Job 的 API 回归测试；Dev Container 全量门禁通过（322 passed、81.22%） | 合并 PR 后继续 T20/T21/T22 真实回放 |
| 2026-09-09 | 代码审查修复（Proof/Report，`6dfc0db`、`97115eb`） | `/code-review high --fix` 定位 7 处问题，已修复 5 处正确性缺陷并提交：Sandbox 状态 `is`→`==`、proof 输出文件名改为 `result.json`、移除报告版本过早读取、报告 job/幂等键按格式区分、调度器放行 pdf | Q-006/Q-007 两项待跟进 |
| 2026-09-09 | T22 任务可观测性摘要 | API 提供任务 Jobs、事件、Finding 状态和结构化失败码汇总，Web 任务页加载并展示 Job 状态汇总 | 浏览器全链路和最终验收报告 |
| 2026-09-09 | T22 事件载荷可观测性 | Web 事件时间线支持展开查看结构化 payload，便于追踪策略、Job 和任务状态变化 | 浏览器链路和最终验收报告 |
| 2026-09-09 | T20 Web Proof/Exploit 操作 | Finding 详情提供脚本引用、镜像摘要输入及 Proof 发起；仅 confirmed Finding 且项目开启利用验证时显示 Exploit | 真实 Runner HTTP 回放与策略拒绝验收 |
| 2026-09-09 | T20 Proof Job 发起接口 | API 新增 Finding Proof/Exploit Job 投递接口，接入 ProofRequest 校验、项目策略和 Outbox 调度 | Web 操作按钮与真实 Runner 回放 |
| 2026-09-09 | T22 Finding 证据链详情 | Web 点击 Finding 后加载证据关系和 Poc 记录并展示工具、强度、摘要和执行状态；Dev Container 内 Svelte 检查通过 | 浏览器完整任务链路和可观测性收口 |
| 2026-09-09 | T21 PDF 报告端到端接入 | API/Worker/Web 支持 PDF，Worker 通过临时文件调用 WeasyPrint 后写入 CAS；Dev Container 内 Web typecheck/build、Ruff 和 reporting 测试通过 | 真实数据库报告 Job 与浏览器回放 |
| 2026-09-09 | T20 无害 Proof/Exploit 容器回放（`d0bcac0`） | 固定 `vulnweaver-proof:fixed` 镜像在禁网、只读根、非 root、capabilities drop 和 no-new-privileges 下分别回放两个入口，均 exit 0 | 补齐带 CAS 工件的 HTTP Runner 回放；不执行真实利用 |

## 9. 验证记录

| 日期 | 验证项 | 结果 | 未覆盖范围 |
|---|---|---|---|
| 2026-09-10 | T23 定向门禁（隔离资源） | `codex-e2f0-*` 一次性容器、独立网络、tmpfs PostgreSQL：API/迁移/契约 34 passed（含 API Key 保留/清除）；Ruff、Pyright、Svelte、Vite 和 Compose 静态检查通过；测试资源已清除 | 未对既有运行栈执行迁移或浏览器 E2E |
| 2026-09-09 | PR 前全量质量门禁（含集成环境） | Dev Container 内 `pnpm run check` 通过：Ruff、Pyright 0 错误，322 tests passed、1 skipped（Docker runtime 为 opt-in），分支覆盖率 81.22%，contracts tsc 与 svelte-check 0 错误 0 警告；PostgreSQL/Redis 集成测试经 `VULNWEAVER_TEST_ADMIN_DATABASE_URL`/`VULNWEAVER_TEST_REDIS_URL` 指向 compose 服务后完整执行 | T16/T18/T19 真实工具动态验收、T20 HTTP CAS 回放、T21/T22 完整 E2E |
| 2026-09-09 | T21 PDF 定向检查 | Dev Container 内 `svelte-check` 0 错误、0 警告；Vite build 成功；Ruff 通过；`pytest tests/reporting -q`：8 passed；API 测试 2 passed、10 skipped | API/Worker 真实数据库 PDF Job 和浏览器点击链路；API 跳过项因容器内未暴露宿主 55432 端口 |
| 2026-09-09 | 全量质量门禁 | Dev Container 内 318 tests 通过，分支覆盖率 81.56%；Ruff、Pyright、TypeScript、Svelte、PostgreSQL/Redis 集成检查通过 | T16/T18/T19 真实工具动态验收、T20 HTTP CAS 回放、T21/T22 完整 E2E |
| 2026-09-09 | T18 Sandbox HTTP 边界 | `pytest tests/sandbox_runner -q`：10 passed、1 skipped；健康检查、契约校验、bearer token 和断连取消通过 | 独立 Docker runtime 的真实请求仍待执行 |
| 2026-09-09 | T20 远程 Sandbox 接入 | `pytest tests/proof tests/worker -q`：14 passed、18 skipped；`SANDBOX_RUNNER_URL` 配置接入和未配置时结构化失败通过 | 独立 Runner 服务集成环境重跑跳过项 |
| 2026-09-09 | Docker 隔离负向探测 | 固定 Alpine 摘要下验证 UID、禁网、只读根、capability drop、no-new-privileges、进程和内存限制；无残留容器 | 尚未从 `DockerCliRuntime` 入口完成同等完整验收 |
| 2026-09-09 | REVIEW 模型连通性探针 | analysis-worker 通过独立 `model-egress` 访问 OpenAI 兼容 endpoint，`/models` 和 JSON 无害请求返回 200 | 四语言 REVIEW 真实端到端和生产域名白名单代理 |

## 10. 下一步

1. 使用真实数据库任务完成 T21 Markdown/PDF/SARIF 报告 Job 回放，确认成功、拒绝、重放、超时/取消和部分失败语义。
2. 构建并固定 AFL++/CASR 与 Proof 镜像摘要，在独立 Sandbox Runner 中回放无害样本，覆盖预算终止、最小输入、覆盖率、crash cluster 和 Proof/Exploit 两种入口。
3. 使用真实数据库任务完成 T20 Proof/Exploit 的 CAS 工件回放，确认成功、拒绝、重放、超时/取消和部分失败语义。
4. 配置 `analysis-plane` 可达的 REVIEW 模型，完成 C/C++/Python/Java P2 端到端验收；随后执行 T22 浏览器全链路、可观测性和最终报告验收。

更新时间：2026-09-10（Asia/Shanghai）
