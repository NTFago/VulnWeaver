# Agent 动态交接台账

> 本文件只维护当前进度、问题、阻碍、决策摘要、验证结果和下一步。稳定开发规则见 `AGENTS.md`；架构依据为 `系统架构设计与技术选型.md`，实现任务依据为 `系统实现模块拆分.md`。

## 1. 项目目标

构建面向已授权源码仓库和 x86/x64 ELF/PE 二进制的软件漏洞挖掘系统。系统通过智能体编排静态分析、逆向分析、模糊测试、独立复核、最小复现和可选利用验证，输出可追溯的 Finding、证据链和报告。

## 2. 当前工程状态

- **项目名称**：VulnWeaver（漏洞织鉴）
- **当前日期**：2026-09-10（Asia/Shanghai）
- **当前阶段**：P2 源码静态分析代码已完成，待真实 REVIEW 模型四语言端到端验收；P3 二进制分析和 Sandbox Runner 处于工具镜像/动态验收阶段；P4 Proof/Exploit 已完成主要代码接入，待 Runner HTTP 端到端回放；P5 报告、全链路 UI 和 E2E 正在收口。
- **当前分支**：`feat/sprint-final-closeout`（基于最新 `main`，已完成 Q-006/Q-007 修复与全量门禁）。`feat/p4-proof-exploit` 已通过 PR #15 合并入 `main`；远程现仅保留 `main`。
- **当前负责人**：Codex。当前优先处理 T20/T21/T22 的真实回放与最终验收，同时保留 T16/T18/T19 的工具链验收事项。
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
| T20 Proof/Exploit 流程 | 待验证 | Codex | ProofRequest、Poc 持久化、Scheduler/Worker/API、SandboxRunnerClient、固定 profile、HTTP CAS 回放验收，以及 API→Dispatcher→Worker→Runner 完整队列链路回放（真实数据库，Poc `completed/exploitable` 落库）已完成 | 无剩余功能项；正式定级待里程碑全量回归 | 2026-09-10 |
| T21 Markdown/PDF/SARIF 报告 | 待验证 | Codex | 报告生成、派生工件登记、Job/Worker 路由、PDF（补齐 WeasyPrint 系统库）、报告纳入 Poc 统计修复，以及真实数据库三种格式报告 Job 回放与 API 下载验收（Markdown `Proof runs: 1`、SARIF 2.1.0、PDF `%PDF`）已完成 | 浏览器端下载链路验收归 T22 | 2026-09-10 |
| T22 全链路 UI、可观测性与 E2E | 待验证 | Codex | 浏览器全链路验收完成：登录→项目→任务页→Finding 详情（证据/POC/复现记录、Proof/Exploit 入口）→报告下载；可观测性（Job 汇总、事件时间线载荷展开、LIVE）已验证；最终验收报告见 `code/docs/progress/2026-09-10-acceptance-report.md` | 里程碑全量回归与真实模型/工具验收归 P2/T16/T18/T19 | 2026-09-10 |

## 4. 当前问题

| ID | 问题 | 影响 | 当前处理 | 状态 | 负责人 |
|---|---|---|---|---|---|
| Q-003 | Windows Python 3.12 在含中文路径的工作区中读取 uv editable `.pth` 可能失败 | Windows 宿主直接使用 editable workspace 不稳定 | Windows 使用 `uv sync --no-editable`，项目门禁统一在 Dev Container/Linux 执行 | 待处理 | 未分配 |
| Q-005 | 复核源码事实目前主要是位置附近的有界片段和 PAIR 关系快照，尚未自动扩展跨函数调用邻域 | 复杂跨函数问题的模型召回率可能受影响；安全门禁仍会阻止弱事实确认 | 先以真实 P2 样本评估，必要时再扩展事实读取范围 | 待处理 | 未分配 |
| Q-006 | Proof/Exploit 创建接口未校验客户端传入的 `script_ref` 是否归属当前 Finding 的 task 项目 | 用户可传入其他项目共享 CAS 存储中的派生对象引用，沙箱仅校验引用存在性，可能越出 Finding 项目范围执行脚本 | 已修复：Scheduler 与 Executor 通过 `find_project_version_by_object_ref` 按项目范围解析 `script_ref`，跨项目或未登记引用被拒绝（`proof.script_ref_outside_project`） | 已处理 | Codex |
| Q-007 | ProofJobExecutor 的数据库事务横跨长时间沙箱 HTTP 调用 | 沙箱运行期间（默认最长 120s）持续占用一条 DB 连接，并发下可能耗尽连接池阻塞其他 DB 工作 | 已修复：拆分为「加载校验事务 → 无事务沙箱调用 → Poc 持久化事务」三段，SQLAlchemy 连接不再被沙箱调用占用 | 已处理 | Codex |
| Q-008 | 任务聚合并集推导不允许跨阶段跳跃；若 Job 脱离正常管线（如手工向 `created` 任务挂 Proof Job），settlement hook 抛 `IllegalTransitionError` 并反复重试形成毒消息 | 非常规入口的 Job 会无限重试、重复触发沙箱执行 | 正常管线不触发；暂以运维规范约束（Job 必须经编排登记），必要时改为容错跳阶段或死信 | 待处理 | 未分配 |

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

## 8. 最近完成记录

| 日期 | 任务/变更 | 验证结果 | 后续工作 |
|---|---|---|---|
| 2026-09-10 | T22 浏览器全链路验收与最终验收报告 | 重建 web 镜像后经浏览器自动化验证：登录、任务页可观测性（状态汇总/Jobs/事件载荷展开）、Finding 详情（复现记录 EXPLOITABLE、Proof/Exploit 入口）、报告下载点击触发下载；验收报告归档 `code/docs/progress/2026-09-10-acceptance-report.md` | 里程碑回归与 T16/T18/T19/P2 真实环境验收 |
| 2026-09-10 | T20 全链路 + T21 真实数据库报告回放 | 重建 analysis-worker/api/migrate 镜像（补 `vulnweaver-proof` 依赖、WeasyPrint 系统库），配 `SANDBOX_RUNNER_URL` 后：API 提交 Proof Job 经 Dispatcher/Worker/Runner 全链路成功（Poc `completed/exploitable`）；Markdown/SARIF/PDF 报告 Job 真实数据库回放成功并可经 API 下载；修复报告渲染未纳入 Poc 的问题（Markdown/HTML 现显示 Proof runs）。Dev Container 门禁 329 passed | T22 浏览器全链路收口 |
| 2026-09-10 | T20 HTTP Runner CAS 回放验收（`feat/sprint-final-closeout`） | 修复 runner 镜像缺 docker-cli（Debian 13 拆包）与 runtime 重复传递镜像 ENTRYPOINT 两个缺陷后，经 `http://sandbox-runner:8080` 完成：CAS 脚本 Proof 回放成功、scheduler 幂等重放同 Job、exploit 未开启项目策略拒绝、失败脚本结构化部分失败且 Poc 留痕；`tests/proof/test_http_replay.py` 4 用例通过，全量门禁 328 passed / 81.38% | 完整 API→Worker 队列链路重跑归 T22 收口 |
| 2026-09-09 | Q-006/Q-007 安全与事务修复（`feat/sprint-final-closeout`） | Proof/Exploit 的 `script_ref` 现按项目范围解析归属（同 digest 可跨项目登记，全局解析不安全）；ProofJobExecutor 拆分事务，沙箱 HTTP 调用不再占用 DB 连接。Dev Container 全量门禁通过：328 passed、覆盖率 81.40%，Ruff/Pyright/Svelte 0 错误 | 继续推进 T16/T18/T19/T20/T21/T22 真实环境验收 |
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
| 2026-09-10 | T22 浏览器全链路 | 浏览器自动化走通登录→项目→任务→Finding 详情→报告下载；事件载荷可展开查看结构化 JSON；截图与 DOM 快照留证 | 真实上传新样本的完整分析链路（依赖真实 REVIEW 模型） |
| 2026-09-10 | T20/T21 完整队列链路回放 | 真实数据库：Proof Job API 202 → Dispatcher → Worker → HTTP Runner → CAS，Poc `completed/exploitable`；Markdown/SARIF/PDF 报告 Job succeeded 且 API 下载返回正确内容（`%PDF` 9.3KB、SARIF 2.1.0、Markdown Proof runs: 1） | 浏览器 UI 点击链路（T22）；报告重投曾因手工注入畸形流消息与消费者组偏移卡顿，已用 `XGROUP SETID 0` 恢复，属运维操作非代码缺陷 |
| 2026-09-10 | T20 HTTP 回放（live Runner） | `pytest tests/proof -q`：15 passed（含 4 个 opt-in HTTP 用例：成功回放、幂等重放、策略拒绝、部分失败）；SandboxRequest 经禁网、非 root、只读输入、资源限制的真实容器执行，产物写回 CAS | 未经 API→Dispatcher→Worker 完整队列链路；Proof 镜像摘要依赖本地构建的 `vulnweaver-proof:fixed` |
| 2026-09-09 | Q-006/Q-007 修复全量质量门禁 | Dev Container 内 `pnpm run check` 通过（含 `VULNWEAVER_TEST_ADMIN_DATABASE_URL`/`VULNWEAVER_TEST_REDIS_URL` 集成环境）：328 tests passed、1 skipped（Docker runtime opt-in），分支覆盖率 81.40%；新增 tests/proof/test_scheduler.py 覆盖跨项目 script_ref 拒绝、同 digest 跨项目解析、无事务沙箱调用路径 | T16/T18/T19 真实工具动态验收、T20 HTTP CAS 回放、T21/T22 完整 E2E |
| 2026-09-09 | PR 前全量质量门禁（含集成环境） | Dev Container 内 `pnpm run check` 通过：Ruff、Pyright 0 错误，322 tests passed、1 skipped（Docker runtime 为 opt-in），分支覆盖率 81.22%，contracts tsc 与 svelte-check 0 错误 0 警告；PostgreSQL/Redis 集成测试经 `VULNWEAVER_TEST_ADMIN_DATABASE_URL`/`VULNWEAVER_TEST_REDIS_URL` 指向 compose 服务后完整执行 | T16/T18/T19 真实工具动态验收、T20 HTTP CAS 回放、T21/T22 完整 E2E |
| 2026-09-09 | T21 PDF 定向检查 | Dev Container 内 `svelte-check` 0 错误、0 警告；Vite build 成功；Ruff 通过；`pytest tests/reporting -q`：8 passed；API 测试 2 passed、10 skipped | API/Worker 真实数据库 PDF Job 和浏览器点击链路；API 跳过项因容器内未暴露宿主 55432 端口 |
| 2026-09-09 | 全量质量门禁 | Dev Container 内 318 tests 通过，分支覆盖率 81.56%；Ruff、Pyright、TypeScript、Svelte、PostgreSQL/Redis 集成检查通过 | T16/T18/T19 真实工具动态验收、T20 HTTP CAS 回放、T21/T22 完整 E2E |
| 2026-09-09 | T18 Sandbox HTTP 边界 | `pytest tests/sandbox_runner -q`：10 passed、1 skipped；健康检查、契约校验、bearer token 和断连取消通过 | 独立 Docker runtime 的真实请求仍待执行 |
| 2026-09-09 | T20 远程 Sandbox 接入 | `pytest tests/proof tests/worker -q`：14 passed、18 skipped；`SANDBOX_RUNNER_URL` 配置接入和未配置时结构化失败通过 | 独立 Runner 服务集成环境重跑跳过项 |
| 2026-09-09 | Docker 隔离负向探测 | 固定 Alpine 摘要下验证 UID、禁网、只读根、capability drop、no-new-privileges、进程和内存限制；无残留容器 | 尚未从 `DockerCliRuntime` 入口完成同等完整验收 |
| 2026-09-09 | REVIEW 模型连通性探针 | analysis-worker 通过独立 `model-egress` 访问 OpenAI 兼容 endpoint，`/models` 和 JSON 无害请求返回 200 | 四语言 REVIEW 真实端到端和生产域名白名单代理 |

## 10. 下一步

1. 使用真实数据库任务完成 T21 Markdown/PDF/SARIF 报告 Job 回放，确认成功、拒绝、重放、超时/取消和部分失败语义。
2. T20 已完成 HTTP Runner CAS 回放（策略拒绝/重放/部分失败通过）；剩余为经 API→Dispatcher→Worker 完整队列链路重跑一次，归入 T22 收口。
3. 构建并固定 AFL++/CASR 镜像摘要，在独立 Sandbox Runner 中回放无害样本，覆盖预算终止、最小输入、覆盖率、crash cluster（T19）。
4. 配置 `analysis-plane` 可达的 REVIEW 模型，完成 C/C++/Python/Java P2 端到端验收；随后执行 T22 浏览器全链路、可观测性和最终报告验收。

更新时间：2026-09-10（Asia/Shanghai）
