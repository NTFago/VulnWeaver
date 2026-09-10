# Agent 动态交接台账

> 本文件只维护当前进度、问题、阻碍、决策摘要、验证结果和下一步。稳定开发规则见 `AGENTS.md`；架构依据为 `系统架构设计与技术选型.md`，实现任务依据为 `系统实现模块拆分.md`。

## 1. 项目目标

构建面向已授权源码仓库和 x86/x64 ELF/PE 二进制的软件漏洞挖掘系统。系统通过智能体编排静态分析、逆向分析、模糊测试、独立复核、最小复现和可选利用验证，输出可追溯的 Finding、证据链和报告。

## 2. 当前工程状态

- **项目名称**：VulnWeaver（漏洞织鉴）
- **当前日期**：2026-09-11（Asia/Shanghai）
- **当前阶段**：T38 按项目负责人决策移除全部计算资源限制（ADR-025）、模型网关上下文自动裁剪、DeepSeek/GLM 供应商预设，已合并 origin/main 最新修复（PR #55-#58）；实现与 E2E 驱动的三项链路修复（Ghidra 地址归一化、本地镜像摘要解析、fuzz 派发幂等与 0020 迁移）完成，Dev Container 全量门禁 479 passed / 5 skipped、覆盖率 ≥80%、Ruff/Pyright/tsc/svelte-check 0 错误、契约无漂移；真实模型 E2E：源码链路（静态+语义审计+复核+报告 9/9 Job 成功）、二进制链路（Ghidra 伪代码+逆向规划智能体+可读化）全通；fuzz 链路跑通派发与沙箱编译，最终以结构化 `fuzz.harness_failed`（模型生成 harness 两轮未编译通过，设计内的 PARTIAL 语义）收尾。
- **当前分支**：`dev`（自 `main@c3f571d` 新建，已 rebase 至 `origin/main@0f1df82`，随后整体推送）
- **当前负责人**：Codex（T38）
- **最近一次全量门禁**：T35 worktree 的 Linux Dev Container 内 `pnpm run check` 全绿：437 passed、5 skipped（均为需 live Runner/Docker 的 opt-in 项），覆盖率 82.11%，Ruff/Pyright/TypeScript/Svelte 均 0 错误。基础 Compose 镜像已重建，宿主 `http://127.0.0.1:8080/` 与经 Web 代理的 `/api/auth/installation` 均返回 200。
  - 注意：本工作区使用 `uv sync --no-editable`，依赖包以**副本**装入 `.venv`，修改 `packages/` 源码后必须重跑 `uv sync --all-packages --no-editable`（必要时加 `--reinstall`）才会被测试进程加载，否则测试会静默使用旧代码。
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
| T16 DIE/UPX/Ghidra/angr 适配 | 已完成 | Codex | ELF/PE 解析、事实提取和 Worker 接入已完成；`apps/binary-tools` 固定镜像（DIE 3.21 + Ghidra 12.1.3 + UPX + objdump）与 `vulnweaver-binary-entrypoint` 经独立 Sandbox Runner HTTP 回放验收：DIE 识别 GCC 14.2.0、Ghidra 19 函数反编译导出伪代码、objdump 21 函数/95 指令/34 xref、UPX 正确判定未加壳；Ghidra 项目目录预创建缺陷一并修复。angr 保持可选未启用 | angr 真实执行留待后续按需启用 | 2026-09-10 |
| T17 PAIR 二进制导入与查询 | 已完成 | Codex | 二进制函数/基本块/指令/Xref 导入、地址查询、Worker 和 API 接入已完成 | 最终 Docker 二进制 E2E 随 T16 验收 | 2026-09-09 |
| T18 Sandbox Runner 安全基线 | 已完成 | Codex | Sandbox 契约、无 Shell Docker runtime、隔离输出、禁网、非 root、资源限制、超时取消、CAS 输出、HTTP 服务和独立镜像已完成；摘要钉住的 Proof/Fuzz 两个 profile 均已通过独立 Runner HTTP 动态验收（T20/T19 回放） | 无 | 2026-09-10 |
| T19 AFL++/CASR 与崩溃分诊 | 已完成 | Codex | `apps/fuzz-tool` AFL++ 4.33c 固定镜像与 `vulnweaver-fuzz-entrypoint` 完成；Sandbox Runner 注册 ToolSpec 并新增 `/work` exec tmpfs；无害样本回放验收：预算终止（100/3000 次执行精确截止）、最小化输入（afl-tmin，摘要与清单一致）、覆盖率（100%）、崩溃聚类（2 个 SIGABRT 记录入簇） | 无 | 2026-09-10 |
| T19-R2 AFL++/CASR Sandbox 集成 | 已完成 | Codex | 目标/种子 CAS bundle、单次 Runner 调用、summary/manifest/minimized-input 解析和回归测试已完成；真实镜像回放与 worker 侧 `FuzzExecutionService` 全契约校验（FuzzResult succeeded，2 crash_ids）已通过 | 无 | 2026-09-10 |
| T20 Proof/Exploit 流程 | 待验证 | Codex | ProofRequest、Poc 持久化、Scheduler/Worker/API、SandboxRunnerClient、固定 profile、HTTP CAS 回放验收，以及 API→Dispatcher→Worker→Runner 完整队列链路回放（真实数据库，Poc `completed/exploitable` 落库）已完成 | 无剩余功能项；正式定级待里程碑全量回归 | 2026-09-10 |
| T21 Markdown/PDF/SARIF 报告 | 待验证 | Codex | 报告生成、派生工件登记、Job/Worker 路由、PDF（补齐 WeasyPrint 系统库）、报告纳入 Poc 统计修复，以及真实数据库三种格式报告 Job 回放与 API 下载验收（Markdown `Proof runs: 1`、SARIF 2.1.0、PDF `%PDF`）已完成 | 浏览器端下载链路验收归 T22 | 2026-09-10 |
| T22 全链路 UI、可观测性与 E2E | 待验证 | Codex | 浏览器全链路验收完成：登录→项目→任务页→Finding 详情（证据/POC/复现记录、Proof/Exploit 入口）→报告下载；可观测性（Job 汇总、事件时间线载荷展开、LIVE）已验证；最终验收报告见 `code/docs/progress/2026-09-10-acceptance-report.md` | 里程碑全量回归与真实模型/工具验收归 P2/T16/T18/T19 | 2026-09-10 |
| T23 Web 首次注册与产品设置 | 已完成 | Codex（独立 worktree） | Web 一次性管理员注册、事务竞争裁决、认证/CSRF 设置 API、模型 URL/名称/API Key/重试参数设置页、API Key 写后不回显/显式清除、Worker DB 配置读取、迁移、Compose 与升级文档已完成 | 合并后在独立 TLS 部署完成真实浏览器首次启动验收；API Key 按用户选择明文落库，数据库/备份读取者可见 | 2026-09-10 |
| T24 Web 工作台布局与可读性优化 | 已完成 | Codex | 桌面、响应式与字号调整完成；设置页复选框已从通用整宽输入规则中隔离，恢复与说明文字横向对齐 | 无 | 2026-09-10 |
| T25 智能体规划执行框架 | 已完成 | Codex（PR #31） | `orchestrator/agent_loop.py` 通用“规划—执行—观察”循环 + `ActionPlanProposal` 契约；预算与结构化降级；15+2 项测试；已合并入 `main` 并由 T27 逆向规划实际消费 | 真实任务轨迹展示归 T33 浏览器回归 | 2026-09-10 |
| T26 二进制主管线收口（Ghidra 默认可用） | 已完成 | Codex | Sandbox Runner binary-tools 路径已接入 Worker；Runner 自动解析摘要，Worker 通过受保护端点获取摘要；binary-facts 完整事实转换为分析贡献并复用派生工件/PAIR 路径；真实 ELF 回放已成功产出 20 函数、96 指令、33 基本块、31 Xref、18 段伪代码；真实数据库 Job 回放已成功生成派生工件；facts 已补齐 imports/strings；API PAIR、地址定位和调用关系查询定向验收通过；资源/挂载配置已文档化 | 无 | 2026-09-10 |
| T27 逆向分析智能体与混淆特征识别 | 待验证 | Codex（`feat/t27-reverse-agent`） | 扁平化启发式识别器 + 新增 `orchestrator/reverse_planning.py`（ReversePlanningAgent 复用 T25 AgentLoop：angr-targeted-analysis 进程内 ToolSpec 经 PolicyEngine 校验、DatabaseAgentRunSink 持久化决策轨迹）；binary executor 新增 `planning_hook`：facts 阶段后由模型基于壳/混淆/函数事实规划 angr 定点目标（`_plan_with_agent` 经 run_angr 闭包真实执行 angr 并合并结果，规划失败结构化降级为固定管线不中断 Job），`target_addresses` 由规划合并进 generation_config；analysis-worker 已装配（模型未配置时自动关闭）；新增 4 项测试（规划执行/降级/Sink 持久化/执行器钩子全链），全量 376 passed | 真实模型差异化规划验收（加壳 vs 未加壳样本）归真实模型 E2E | 2026-09-10 |
| T28 解混淆与可读伪代码生成 | 进行中 | Codex（已合并入 `main`，合并提交 `8897cdd`；分支已清理） | angr 参数校验/缺参回归已补齐；angr 9.3 固定为二进制工具依赖，并通过 binary-facts Sandbox profile 传递受限目标地址；真实 Runner 回放已以新摘要镜像成功执行（`0x1050` symbolic fact=`completed`）；新增自编、无害的 OLLVM 风格 dispatcher 教学源码与恢复回归；控制流标签恢复与可读伪代码派生产物（原始结果、确定性恢复与经地址锚定的模型视图）已实现，模型不可用时自动降级。真实模型可读化回放已完成（真实 Runner Ghidra 伪代码 → DeepSeek 模型 → 4 个候选全部通过地址锚定校验），并修复：空目标地址时 argv 含空串被 Runner 拒绝、模型输出契约失败码/详情透出、DeepSeek json_object 提示词兼容与输出截断（输入边界收紧为 4 函数/16KB） | 获取并隔离构建真实 OLLVM `fla` 编译产物后完成最终验收（obfuscator-llvm llvm-4.0 源码构建已在 `ollvm-build` 容器进行，预构建 DeClang 发行包确认不含混淆 pass） | 2026-09-10 |
| T29 语义审计智能体（源码+二进制） | 待验证 | Codex（`feat/t29-semantic-audit`） | 新增 `semantic_audit` Job 类型、`SemanticAuditReport` 公共契约与迁移 0017；`SemanticAuditScheduler` 在静态基线结算后每任务幂等调度一个审计 Job（ADR-021 顺序：static → semantic → review，复核钩子同步适配）；`SemanticAuditor` 按函数邻域（PAIR 函数 + 有界源码摘录）调用 AUDIT 档模型，模型 finding 必须锚定到不可变 PAIR 索引（幻觉位置丢弃不落库），以 MODEL_EXPLANATION/CONTEXTUAL 证据投影候选 Finding（与静态投影同 ID 方案，重复候选幂等合并）并进入既有复核与确认门禁；AgentRun 落库可经 agent-runs API 查询。全量门禁 363 passed；二进制侧已接入：`SemanticAuditFinding` 契约支持 address 锚定（oneOf 源码/二进制），审计遍历 ELF/PE/DERIVED 版本的 PAIR 函数并以伪代码为代码上下文，模型 finding 经 `functions_at_address` 锚定 BinaryLocation | 真实模型二进制端到端验收（依赖 T26 沙箱产出伪代码 + AUDIT 模型配置） | 2026-09-10 |
| T30 关键逻辑标定 | 待验证 | Codex（PR #41，已合并） | `CriticalLogicAssessment` 契约与 Python/TS 视图；二进制候选写入 PAIR attributes、模型 verdict 合并与失败降级；analysis-worker 自动装配；函数类别徽章和详情面板均已实现。新增 `test_critical_logic_confirm.py` 覆盖候选暂存、auth/crypto verdict 合并、模型映射和失败降级；同时修复确认钩子签名/JSON 返回值不匹配及 WIP 误覆盖的 orchestrator 导出面。合并 T28 基线后 Linux Dev Container `pnpm run check` 全绿（385 passed、5 skipped、覆盖率 81.97%，ruff/pyright 0，svelte-check 0），契约 --check 无漂移 | 在产品设置配置 PLANNING 模型及二进制工具摘要后，以教学 ELF 验收认证与加解密标定、PAIR API 和前端展示 | 2026-09-10 |
| T31 漏洞自动利用智能体 | 待验证 | Codex（`feat/t31-auto-exploit`） | 新增 `ExploitScript` 公共契约与 `AutoExploitScheduler`：复核结算后对 confirmed 且项目开启利用验证的 Finding 自动投递 EXPLOIT Job（幂等，未确认/未开启自动跳过）；`ExploitScriptGenerator` 执行期按 Finding 事实调用 PLANNING 档模型生成脚本，经 `validate_generated_script` 安全红线校验后登记为输入工件的派生版本（可追溯 produced_by/parent），再走既有沙箱 Proof 链路并落 Poc 证据链；5 项新测试覆盖投递门禁、生成执行全链、危险脚本拒绝、钩子自动投递。全量 370 passed | 真实模型端到端（配置 `PROOF_TOOL_IMAGE_DIGEST` + 模型后对教学样本验收） | 2026-09-10 |
| T32 模糊测试接入自动链路与 harness 生成 | 待验证 | Codex（`feat/t32-fuzz-auto`） | 自动投递已接通：`TaskAggregateSettlementHook` 在复核结算后调度 fuzz（与 T31 复用同一项目显式 opt-in `exploit_validation_enabled`，因模糊测试同属动态执行），`FuzzJobScheduler.schedule_finding_in_transaction` 经注入的 `FuzzTargetResolver` 解析目标，解析器仅在「候选类别为内存破坏/注入」且「Finding 锚定工件属于该任务 `artifact_version_ids`」时产出目标，否则拒绝——不会对未授权工件执行动态分析。在既有 FUZZ Job/证据基础上补齐两项 PR #44 遗留验收：①Runner 摘要接口——`ToolRegistry.digests()` 从实际注册表派生摘要，Runner 新增 `GET /v1/tools` 并让 `/v1/tools/{name}/{version}` 一律由注册表作答（不再依赖硬编码映射表），`SandboxRunnerClient` 增加 Bearer 认证与 `registered_tools()`，analysis-worker 在摘要缺失时经该端点发现 `afl-casr` 摘要并注册 ToolSpec；fuzz/proof 镜像摘要支持本地镜像回退（与 binary-tools 一致），compose 补齐 `SANDBOX_RUNNER_TOKEN`/`FUZZ_RUNNER_TIMEOUT_SECONDS`。②harness 编译管线——新增 `HarnessSource` 公共契约（此前 `output_contract="HarnessSource"` 未注册，真实网关必然 `KeyError`）、`harness-compile` 固定 profile（复用 AFL++ 镜像保证插桩 ABI 一致）、`HarnessCompiler`（仅为 harness 源码提交受限沙箱请求并只读回结构化诊断与 CAS 产物）与 `HarnessPipeline`（生成→编译→有界修正，预算耗尽为结构化失败）+ fuzz-tool 入口 `compile_harness`。③`FuzzJobScheduler.schedule` 改为按 `FuzzTarget` 构造真正合法的 `FuzzRequest`（原实现只写 `finding_id`，每个 Fuzz Job 都会 `fuzz.request_required` 失败）；④crash 无法挂接 Finding 时不再静默 `SUCCEEDED`（`fuzz.crash_sink_unconfigured`/`fuzz.crash_finding_required`）；⑤修复 `persist_crash_evidence` 用未排序首元素作挂接时间戳 | 真实镜像 E2E（编译 harness 并受限 fuzz 崩溃挂接 Finding）留待部署 Runner 与登记 AFL/CASR 摘要后执行。种子语料当前取 Finding 锚定工件自身（已同时存在于 fuzz 与 binary-facts CAS，且 bundle 构建器限制总量），属可用但保守的默认；D-002 已接受维持该默认，不新增契约字段 | 2026-09-10 |
| T33 前端逆向工作台与人工复核 | 待验证 | Codex | 任务页新增「函数与调用链」工作台：函数列表点击选中、caller/callee 双列联动跳转、二进制伪代码代码视图；新增「智能体运行轨迹」区（模型、决策数、token、耗时、失败码）渲染 agent-runs；人工复核与标注入口此前已并入 Finding 详情 | 真实二进制样本浏览器回归验证（依赖 T26 沙箱链路产出伪代码） | 2026-09-10 |
| T34 报告证据链写实 | 待验证 | Codex（`feat/t32-fuzz-auto`） | PR #44 遗留的“稳定 Finding 投影字段”已落地为 `Finding.call_path`：`CallPathStep` 公共契约、`findings.call_path` NOT NULL 列与迁移 0018、Python/TS 绑定；`vulnweaver_pair.build_call_path_steps` 为纯函数投影（仅取 `call` 边、经节点→函数映射解析二进制指令节点、去重并上限 64），静态投影与语义审计两处 Finding 构造点分别经一次共享邻域读取填充；持久化读写对称（`_canonical_finding` 规范化，避免幂等 `create` 自冲突）。三类报告消费：Markdown `### Call path` 段、HTML/PDF `<ul>` 段、SARIF `codeFlows[].threadFlows[].locations`（源码步骤为 path:line，二进制步骤为 `binary://0x…`）。同时修复 PairEdge 行映射未做枚举转换（`type` 读回为裸字符串，`is` 比较静默丢失全部调用边）。既有严重等级/修复建议/证据摘要/crash stack 能力保留 | 真实报告 Job 端到端（生成含调用路径的 Markdown/PDF/SARIF 并经 API 下载）与独立 SARIF Schema 校验留待部署环境执行 | 2026-09-10 |
| T35 主分支全链路接线修复 | 已完成 | Codex（`codex/fix-main-review`） | PLANNING/REVIEW/AUDIT 共用产品模型配置；源码无静态扫描器与二进制导入均会进入语义基线；动态 Job 创建后重新聚合；默认 Markdown 在结算前自动投递；源码 Harness 读取有界摘录并走生成→沙箱编译→安全解包→Fuzz，ELF 直接 Fuzz、PE 明确拒绝；Compose 默认回环暴露 Web 并透传摘要；前端 WebSocket 补事件后重连，人工复核可选结果并显示历史 | 真实 PLANNING 模型 + AFL/Proof 固定镜像的动态 E2E 仍属部署验收，不影响代码任务完成 | 2026-09-10 |
| P2 大归档源码摘录修复 | 待验证 | Codex（`fix/large-archive-excerpts`） | 真实模型任务确认配置和调用正常，但 95 MiB `BettaFish.zip` 被摘录器的 16 MiB 完整归档读取上限拒绝，模型仅得到函数元数据而无法审计源码；现改为校验归档元数据后只解压请求的源码文件，并缓存同一 Reader 内的 CAS 完整性校验。Linux 运行镜像定向测试 21 passed、Ruff 通过；已用真实 BettaFish 工件成功读取 `BettaFish/ReportEngine/llms/base.py`（426 bytes，未截断），Worker 已重建并运行 | 在 Web 重新投递 BettaFish，确认模型输入含源码摘录、任务不再出现 `excerpt_archive_too_large`，并检查审计和报告结果 | 2026-09-11 |
| T37 Markdown 快速路径 CI 修复 | 已完成 | Codex（`ci/markdown-gate-move-gate`，PR #53 已合并） | Q-017 登记；Markdown gate 移入具备全量克隆的 `change-scope` job（浅克隆无 base 对象、`persist-credentials: false` 不可 fetch）；修复 PR #53 全量门禁通过；本收尾 PR（markdown-only）的快速路径 CI 实跑为绿，Q-017 关闭 | 无 | 2026-09-11 |

| T38 移除计算资源限制与模型提供商预设 | 进行中 | Codex（`dev` 分支） | ADR-025：Policy Engine 预算门禁、沙箱容器配额（CPU/内存/PID/tmpfs size/输出限额/规格超时拒绝）、`bounded_resource_budget` 收敛、review/audit `model_budget_exhausted` 全部删除；`resource_budget` 保留为惰性簿记（API 写入无界常量、任务预算可省略并继承项目）；网关新增 `_fit_context_window` 自动裁剪 + `review_model_context_window_tokens`；设置页新增 DeepSeek/GLM 预设并移除预算表单；E2E 驱动修复：Ghidra 地址按 image base 归一化（伪代码进入 PAIR 工作台）、Runner 本地摘要优先取 RepoDigests（containerd 守护进程无法解析旧 CLI 的 config digest）、fuzz 派发幂等（确定性 job id 预检 + 并发容忍 + 0020 迁移补 `ck_jobs_kind` 的 fuzz 值 + harness run id 按 attempt/轮次隔离）；AGENTS.md 红线第 4 条同步改写 | 推送 `origin/dev` 并确认 CI；`fuzz.harness_failed` 依赖模型生成质量（结构化 PARTIAL 属设计内），auto-exploit 链路需 confirmed Finding 未在 E2E 触发 | 2026-09-11 || T36 Web 设置默认页与界面现代化改版 | 已完成 | Codex（`feat/web-settings-first-modernization`，PR #49 已合并） | 设置改为登录后默认页并置于导航第一位（注册、登录、首次改密完成后均落在设置页）；修复设置页复核模型字段重复渲染缺陷；任务页指标卡以「已完成执行单元 x/y」替代原始 JSON 串；`app.css` 重写为令牌化设计系统（控件 8px / 面板 12px 半径锁、单一青柠强调色、语义状态色、焦点环、reduced-motion 降级）；设置页新增锚点分区导航；复核/标注操作区拆分为两组修复按钮换行；移动端导航胶囊拉伸修复 | 部署环境（重建 Web 镜像）后的真实浏览器回归归里程碑验证 | 2026-09-10 |

| T38 报告下载与导出可读性修复 | 已完成 | Codex（`fix/report-download`） | 下载响应按报告格式返回安全文件名和媒体类型；Markdown/HTML/SARIF 读取规范源码范围，二进制位置读取 `virtual_address`；前端显示报告生成失败原因并为下载链接提供扩展名 | 部署更新后的 API/Web 镜像后做浏览器点击回归 | 2026-09-11 |
| T39 任务事件契约兼容与部署镜像一致性修复 | 已完成 | Codex（`fix/task-event-stream`） | 读取历史 `task.status_changed` 事件时对缺失的可空 `failure` 做内存兼容补全；为严格 Pyright 检查补充 `JsonObject` 类型收窄，避免兼容 payload 展开产生未知类型；统一重建 API、Dispatcher、Orchestrator、Worker、Sandbox Runner、Web 镜像；清理开发 Redis DB 0 残留队列；保留 PostgreSQL 任务和工件数据 | 无；用户刷新当前任务页即可确认页面恢复最终状态 | 2026-09-11 |

### 3.1 课设差距补齐任务包定义（T25-T34）

依据：对照《2026 网络空间安全课程设计》题目要求与代码实际的差距分析（Q-009）。所有任务包对应《系统实现模块拆分》既有模块（M01/M07/M10/M11/M13/M14/M15/M16）的验收标准，不改变架构与安全红线。

**T25 智能体规划执行框架**（P0；依赖：无；对应 M07/M05）
- 现状：全系统唯一 LLM 生产调用是独立复核（`orchestrator/model_reviews.py`）；`ActionPlan`/PolicyEngine/AgentRun 基础设施齐备但无规划智能体驱动；LangGraph 编排为固定 4 节点 intake 状态机。
- 目标：提供统一的“规划—执行—观察”循环：模型按任务上下文输出结构化 ActionPlan，经 Policy Engine 校验后调度已登记工具/Job，结果回填上下文继续迭代，直至完成或预算耗尽；决策序列与理由写入 AgentRun。
- 验收：循环推进、策略拒绝、预算终止、模型未配置/连续失败时结构化降级到固定管线均有自动化测试；决策轨迹可经 `GET /api/tasks/{id}/agent-runs` 查询。

**T26 二进制主管线收口**（P0；依赖：无；对应 M10/M11）
- 现状缺陷：`compose.yaml` 中 `GHIDRA_HEADLESS_EXECUTABLE` 默认为空且 analysis-worker 镜像未安装 Ghidra；`BINARY_TOOLS_IMAGE_DIGEST` 默认为空且 binary-facts 沙箱工具无任何调度方（死路径）；二进制任务仅 1 个 IMPORT Job，结束即 `NO_FINDINGS`，伪代码从不进入审计。
- 目标：默认部署下 Ghidra 反编译可用（worker 镜像内置或经 Sandbox Runner binary-tools 路径接通，二选一并记录决策）；伪代码、函数、调用关系入库 PAIR。
- 验收：默认 compose 上传 ELF 教学样本后，`GET /api/tasks/{id}/pair` 返回含伪代码的函数清单与调用关系。

**T27 逆向分析智能体与混淆特征识别**（P0；依赖：T25、T26；对应 M07/M10）
- 现状：二进制分析为固定步骤序列（`binary-analysis/executor.py`）；“是否脱壳/是否解混淆”无模型决策；`target_addresses` 恒为空无人规划；无混淆特征识别代码。
- 目标：解析格式/壳指纹/混淆特征（控制流平坦化启发式：分发基本块聚集、间接跳转密度）后，由模型自主规划分析步骤（是否脱壳、反编译目标函数、是否解混淆、angr 定点目标），经 T25 循环协同调用去壳/反编译/解混淆工具。
- 验收：加壳与未加壳 ELF 教学样本分别获得差异化且可追溯的规划（AgentRun 含决策理由）；无模型时降级为现行固定管线并输出结构化说明；`target_addresses` 由规划填充。

**T28 解混淆与可读伪代码生成**（P1；依赖：T26；对应 M10）
- 现状缺陷：`angr_helper.main` 参数校验为 `!= 7` 而实际传入 10 个 argv（且函数体读取 `argv[9]`），angr 分支启用即失败；全仓无混淆检测/解混淆实现。
- 目标：修复 argv 校验并在 `ANGR_ENABLED=true` 下端到端可用；控制流平坦化恢复（反扁平化脚本或 Ghidra 脚本）；LLM 对伪代码做结构归纳、变量重命名、注释，生成“可读版本”派生工件，原始反编译结果保留不改写。
- 验收：OLLVM 平坦化教学样本产出混淆判定与可读版本工件（派生谱系完整）；angr 路径真实执行成功。

**T29 语义审计智能体（源码+二进制）**（P0；依赖：T26（二进制侧）；对应 M07/M15）
- 现状：源码审计仅 2 条固定 Semgrep 规则投影 Finding，LLM 只复核不发现；二进制路径不产生 Finding（`evidence_ids=[]`），报告只消费 findings/pocs。
- 目标：落地 ADR-021 审计计划（必跑基线 + 覆盖度门禁）；LLM 按函数邻域（源码）/伪代码+调用邻域（二进制）语义审计产出候选 Finding，进入既有独立复核与确认门禁。
- 验收：C 或 Python 教学样本发现固定规则之外的候选漏洞并经独立复核；ELF 教学样本经伪代码审计端到端产出候选 Finding、完成复核并生成报告。

**T30 关键逻辑标定**（P1；依赖：T26；对应 M07/M11/M01）
- 现状：全仓无任何认证/加解密/注册等关键函数识别代码；前端无标定展示。
- 目标：导入表/字符串/tree-sitter 特征规则 + LLM 确认，标定关键函数并入库（PAIR 属性或专表），记录判定依据与证据；API 与前端展示函数位置、关联代码、调用链。
- 验收：教学样本标定出至少认证与加解密两类关键函数，前端可见位置、关联代码与判定依据。

**T31 漏洞自动利用智能体**（P1；依赖：T25；对应 M14/M07）
- 现状：Proof/Exploit 需用户手工提供 `script_ref` 与镜像摘要，无自动生成。
- 目标：对 `confirmed` 且项目开启利用验证的 Finding，由模型自动生成 PoC/利用脚本（受 Policy、资源预算与利用红线约束：无持久化/横向/外联），自动经 Sandbox Runner 执行验证，脚本、日志与结果作为证据链落库。
- 验收：confirmed 教学漏洞在无人工输入下完成“生成 → 沙箱执行 → `exploitable`/`not_exploitable_under_environment` 落库”全链；生成脚本经策略校验。

**T32 模糊测试接入自动链路与 harness 生成**（P2；依赖：T25（可选）；对应 M13/M07）
- 现状：AFL++/CASR 工具链回放验收通过（T19），但不在自动管线中，无 LLM harness 生成。
- 目标：按 Finding 或审计计划自动创建 fuzz Job；LLM 生成 harness 并进入“编译—诊断—修正”有界循环（超限结构化失败，Task 可 PARTIAL）；崩溃簇与最小化输入挂接 Finding 证据。
- 验收：教学样本自动完成 harness 生成与受限时长 fuzz，崩溃簇作为 Evidence 关联到 Finding。

**T33 前端逆向工作台与人工复核**（P1；依赖：T26、T30 数据就绪；对应 M01/M02）
- 现状：前端为单文件最小闭环（`apps/web/src/App.svelte`），未调用 pair/agent-runs/annotations 任何端点；API 缺函数调用边端点；人工复核与标注 API（`app.py` annotations/review）完整但无前端入口。
- 目标：API 暴露函数调用边；函数点击高亮 caller/callee 并联动伪代码与判定依据；Agent 决策轨迹展示；人工复核提交与标注修正（label/note/severity）入口。
- 验收：浏览器完成“二进制样本 → 函数浏览 → 调用链高亮 → 伪代码查看 → 提交标注”操作；标注不覆盖原始分析与历史复核。

**T34 报告证据链写实**（P1；依赖：T29、T31（内容源）；对应 M16）
- 现状：报告证据链仅计数（"Evidence: N"），PDF 无严重等级，SARIF 无修复建议。
- 目标：三类报告包含证据链明细：文件位置/二进制地址、调用路径、Review/Poc 验证结果、证据工件摘要与引用；PDF 补严重等级。
- 验收：报告四要素（漏洞列表、严重等级、证据链、修复建议）在 Markdown/PDF 齐备；SARIF 通过 Schema 校验且含修复建议字段。

## 4. 当前问题

| ID | 问题 | 影响 | 当前处理 | 状态 | 负责人 |
|---|---|---|---|---|---|
| Q-003 | Windows Python 3.12 在含中文路径的工作区中读取 uv editable `.pth` 可能失败 | Windows 宿主直接使用 editable workspace 不稳定 | Windows 使用 `uv sync --no-editable`，项目门禁统一在 Dev Container/Linux 执行 | 待处理 | 未分配 |
| Q-005 | 复核源码事实目前主要是位置附近的有界片段和 PAIR 关系快照，尚未自动扩展跨函数调用邻域 | 复杂跨函数问题的模型召回率可能受影响；安全门禁仍会阻止弱事实确认 | 先以真实 P2 样本评估，必要时再扩展事实读取范围 | 待处理 | 未分配 |
| Q-006 | Proof/Exploit 创建接口未校验客户端传入的 `script_ref` 是否归属当前 Finding 的 task 项目 | 用户可传入其他项目共享 CAS 存储中的派生对象引用，沙箱仅校验引用存在性，可能越出 Finding 项目范围执行脚本 | 已修复：Scheduler 与 Executor 通过 `find_project_version_by_object_ref` 按项目范围解析 `script_ref`，跨项目或未登记引用被拒绝（`proof.script_ref_outside_project`） | 已处理 | Codex |
| Q-007 | ProofJobExecutor 的数据库事务横跨长时间沙箱 HTTP 调用 | 沙箱运行期间（默认最长 120s）持续占用一条 DB 连接，并发下可能耗尽连接池阻塞其他 DB 工作 | 已修复：拆分为「加载校验事务 → 无事务沙箱调用 → Poc 持久化事务」三段，SQLAlchemy 连接不再被沙箱调用占用 | 已处理 | Codex |
| Q-008 | 任务聚合并集推导不允许跨阶段跳跃；若 Job 脱离正常管线（如手工向 `created` 任务挂 Proof Job），settlement hook 抛 `IllegalTransitionError` 并反复重试形成毒消息 | 非常规入口的 Job 会无限重试、重复触发沙箱执行 | 已修复：`_transition_path` 只输出状态机允许的迁移（越阶段跳被跳过），结算钩子对残余非法迁移记录 `task_aggregation_transition_skipped` 并继续；回归测试确认越阶段 Proof Job 正常结算且任务仅经合法迁移收尾 | 已处理 | Codex |
| Q-009 | 对照课设要求差距分析（2026-09-10，只读核查确认）：①全系统唯一 LLM 生产调用是独立复核，无自主规划智能体，ActionPlan/LangGraph 均为固定管线；②二进制主管线默认无 Ghidra（env 空且 worker 镜像未装），binary-tools 沙箱工具为死路径，二进制任务不产生 Finding；③无关键逻辑标定、无混淆识别/解混淆（`angr_helper.py:13` argv 校验 `!=7` 与实际 10 参数不符，启用即失败）；④模糊测试未接入自动管线、无 harness 生成；⑤利用需手工提供 script_ref；⑥前端无调用链/伪代码/Agent 轨迹/人工复核标注展示；⑦报告证据链仅计数，PDF 无严重等级 | 课设题目核心要求（多智能体协作、二进制逆向自主规划、伪代码漏洞检测、关键逻辑标定、自动利用、证据链报告）未覆盖，T01-T24 的“全部完成”是对裁剪后范围而言 | 已建立补齐任务包 T25-T34（定义见 3.1），按 P0（T25/T26/T27/T29）→P1（T28/T30/T31/T33/T34）→P2（T32）顺序实施。截至 2026-09-10：①⑤⑥⑦ 已实现（T25/T31/T33/T34），②③ 已实现（T26/T27/T28/T30），④ 已实现（T32：自动投递 + harness 生成/编译 + crash 证据挂接），仅剩真实镜像 E2E 未执行；种子语料维持“即目标工件”默认（D-002 已接受） | 待处理 | Codex |

| Q-010 | 前端硬编码的项目资源预算（`cpu_millis: 2000`）低于随部署发布的 ToolSpec（`binary-import` 8000、`semgrep`/`cppcheck` 4000），且项目预算无更新端点 | Policy Engine 比较「工具规格 ≤ 项目预算」，于是从 Web UI 建的项目在初始 Job 之前即被拒（二进制任务）、或在静态工具阶段被拒（源码任务），任务静默失败且用户无法自救 | 已修复：前端移除硬编码常量，项目表单可展开填写 7 项预算（留空即用服务端默认）；API 新增 `vulnweaver-tool-runtime` 依赖与 `TOOL_SPEC_DIRECTORY` 挂载，按已注册规格逐项最大值推导默认与下界，低于下界以 `resource_budget_below_tool_requirements` 拒绝并点名资源项；`tests/api/test_budgets.py` 直接加载真实 `deploy/tool-specs` 守卫两侧一致 | 已处理 | 本次修复分支 |
| Q-011 | 编排层的结构化失败（`OrchestrationError.failure`）既不落库也不进 `task.status_changed` payload，orchestrator 日志行亦不含失败码 | `_fail_task` 恰恰发生在没有 Job 存在时，因此 `/api/tasks/{id}` 与事件流都没有任何原因，前端只能显示"失败"，定位必须重放编排流程 | 已修复（ADR-023）：`tasks.failure` 列（迁移 `0019_task_failure`）、`Task.failure` 与 `TaskStatusChangedPayload.failure` 均为 required 可空字段，逐字对齐既有 `Job` 形状；**两条失败路径都带原因**——`_fail_task`（无 Job 时）落库 `error.failure`，任务聚合的 `_task_failure`（全部 Job 失败/取消且无成功）取最早失败 Job 的结构化失败并附 `job_id`/`job_kind`；前端任务页展示失败码与原因；orchestrator 日志补 `failure_code`/`failure_details` | 已处理 | 本次修复分支 |
| Q-012 | `Orchestrator.process_once` 的 `read_group` / `ensure_group` / `claim_stale` / `acknowledge` 均无兜底，`QueueUnavailable` 直接掀掉进程；`ReliableWorker.run` 存在完全相同的洞 | Redis 卡顿超过客户端 socket 超时（5s）即崩溃重启；另一套同分支部署的 orchestrator 已重启 5 次，属 main 既有缺陷，每次重启有恢复空窗 | 已修复：`Orchestrator.run(stop)` 与 `ReliableWorker.run` 接住 `QueueUnavailable`，按 dispatcher 既有退避式（`min(max, base * 2 ** min(attempt-1, 30))`）做停止感知重试，进程不退出；退避参数经 `ORCHESTRATOR_RETRY_*` / `WORKER_RETRY_*` 注入；新增两侧故障注入测试 | 已处理 | 本次修复分支 |
| Q-013 | proof/fuzz 下发给沙箱的 `resource_budget` 方向相反（沙箱要求「请求 ≤ 规格」，UI 却传整个项目预算），且 `deploy/tool-specs/binary-import.json` 的 `cpu 8000 / memory 1 GiB` 与运行时实际值（`cpu 4000 / 3 GiB`，见 `docs/binary-analysis-runtime.md` 与 `binary-analysis/tools.py`）矛盾 | Proof/Exploit 必然 `sandbox.resource_budget_exceeded`（proof-tool 规格仅 cpu 1000 / 256 MiB / 120s）；模糊测试同样超限；ToolSpec 数值无出处，门禁 CPU 过严而内存过松 | 已修复（ADR-024）：`binary-import` 校准到运行时实际值；新增 `vulnweaver_tool_runtime.bounded_resource_budget` 作为唯一收敛实现，proof 执行器与 fuzz 执行器按各自规格收敛（源码静态阶段原私有实现改为复用），运行器侧拒绝语义不变；默认预算 `max_dynamic_runs ≥ 1`，开启利用验证但预算不容许动态运行时建项目即拒 | 已处理 | 本次修复分支 |

| Q-014 | `SANDBOX_RUNNER_TIMEOUT_SECONDS` 默认 60s，低于最长工具超时（binary-facts 允许运行至 600s）：analysis-worker 的沙箱 HTTP 客户端会在工具完成前放弃，二进制任务必然失败于 `ToolExecutionError` | 默认部署下二进制分析完全不可用；且沙箱容器在 Job 已失败后仍在运行，浪费资源 | 已修复：`compose.yaml` 与 `.env.example` 默认值改为 600（`SandboxRunnerClient` 的上限即 600，等于最长工具预算，与既有的 `FUZZ_RUNNER_TIMEOUT_SECONDS=600` 一致）；实时栈实测确认 600s 下 `binary-import` Job 由 failed 转为 succeeded，任务走完 `analyzing→reporting→completed`。**注意**：首次修复时误设为 660，超出客户端 600 上限导致 analysis-worker 直接崩溃，见 Q-015 | 已处理 | 本次修复分支 |
| Q-015 | Q-014 首次修复把 `SANDBOX_RUNNER_TIMEOUT_SECONDS` 默认值设为 660，而 `packages/proof/src/vulnweaver_proof/client.py:27` 校验 `timeout_seconds > 600` 即抛 `ValueError` | **任何未在 `.env` 覆盖该值的部署，analysis-worker 启动即崩溃重启**（`sandbox runner timeout must be between 0 and 600 seconds`），产品完全不可用 | 已修复：默认值改为 600。教训记录：该默认值的上界由客户端契约决定，不能按"工具预算 + 余量"自由设定；若要保留余量需同时放宽客户端上限并补对应测试 | 已处理 | 本次修复分支 |
| Q-016 | 工件卷在全新部署时存在属主竞争：sandbox-runner 以 root 运行，若它先于非 root 的 api/analysis-worker 写入共享卷，`.staging`/`objects` 会被建成 root 属主，非 root 消费者随即因 `PermissionError` 崩溃重启 | **每次全新部署（空卷）都会命中**，表现为 analysis-worker 崩溃循环；手工 `chown` 可解但删卷重建即复现 | 已修复：`compose.yaml` 新增一次性 `artifact-init` 服务，以 root 创建 `.staging`/`objects` 并把工件卷 chown 给 10001，api/analysis-worker/sandbox-runner 均改为依赖其成功完成（orchestrator 不挂载该卷，不依赖）。实测：`down -v` 后全新启动，`artifact-init` exit 0、`analysis-worker` 稳定 Up、卷内三个目录属主均为 10001，无需任何手工操作 | 已处理 | 本次修复分支 |
| Q-017 | Markdown 快速路径 CI 报错退出：`python-quality` job 为浅克隆（depth 1）且 `persist-credentials: false`，先报 `fatal: bad object`（base 对象缺失），补浅取后又因无凭据报 `could not read Username`（PR #50 首次实跑暴露；该检查非必需，红 X 未阻断合并） | 文档类 PR 的门禁信号失真：失败会被常态忽略；若日后把该检查设为必需，所有 docs PR 都会被阻断 | 已修复：把 `Markdown documentation gate` 步骤移入 `change-scope` job——该 job 本就是全量克隆（`fetch-depth: 0`）且分类步骤已在用同样的 BASE/HEAD SHA 执行 `git diff`，零网络零凭据；`python-quality` 在文档类 PR 下仅剩 checkout，按既有设计以成功状态跳过完整门禁。修复 PR 走全量门禁验证，快速路径经修复后的 markdown-only PR 实跑验证（见 T37） | 已处理 | Codex |

| Q-018 | 报告下载接口未返回报告文件名/媒体类型，报告渲染器读取不存在的 `location.line`，二进制位置字段 `virtual_address` 也未被消费 | 浏览器下载得到无扩展名的 `content`；源码位置错误显示为第 1 行，二进制位置显示为 `unknown` | T38 已修复下载响应元数据、Markdown/HTML/PDF/SARIF 的源码范围与二进制地址读取，并补充报告失败状态提示 | 已处理 | Codex |
| Q-019 | 部署栈的 Orchestrator 镜像未随事件契约更新，且 Redis 保留了不含 `failure` 字段的旧任务状态事件；API 事件流对历史事件响应校验失败 | 任务事实已进入 `completed`，但 `/api/tasks/{id}/events` 返回 500，前端无法收到最终状态；Orchestrator 反复因 `MalformedQueueMessage` 退出 | 已处理：历史事件读取兼容补全，所有应用镜像按当前代码重建，并清理开发 Redis DB 0；数据库任务与工件数据未删除 | 已处理 | Codex |

## 5. 当前阻碍点

当前无阻碍。T16/T18/T19/T20/T21/T22/T32/T34 的未完成项属于待验证工作或待确认设计（D-002），不应标记为阻碍：

- T32 真实镜像 E2E 需要先构建并登记含 `compile_harness` 的 `vulnweaver-afl-casr` 新摘要、在 Runner 与 worker 两侧配置该摘要与 `SANDBOX_RUNNER_TOKEN`；这些属于部署前置，可在当前环境外完成。自动投递与目标解析已实现，不依赖 D-002。

## 6. 待确认事项

| ID | 待确认事项 | 推荐默认值 | 决策人 | 状态 |
|---|---|---|---|---|
| D-001 | ADR-021 是否采用“审计计划驱动的必跑基线 + Finding 驱动的条件深审”，并由计划完整性约束 `NO_FINDINGS` | 采用；先完成计划、覆盖度、自动 Markdown 和结算完整性，再扩展检测面与动态分支 | 项目负责人 | 已接受（2026-09-10） |
| D-002 | T32 种子语料是否需要在契约中显式建模（独立于目标工件），还是维持“以任务输入工件自身作为种子”的保守默认 | 维持当前默认即可满足验收（种子即目标工件，bundle 预算仍受限）；仅当需要真实覆盖度时才引入独立种子投影，届时新增契约字段并同步消费者 | 项目负责人 | 已接受（2026-09-10）：维持“种子即目标工件”默认，不新增契约字段 |

已确认决策和完整 ADR 文件见 `code/docs/adr/`；ADR-021 已生效，可按其“实施顺序”开始对应设计任务，生产代码仍须按任务包和验收标准推进。

## 7. 当前相关技术决策

| ADR | 当前决策 |
|---|---|
| ADR-006 | 动态执行只能由独立 Sandbox Runner 负责，控制面和普通 Worker 不挂载 Docker Socket。 |
| ADR-008 | Python 使用 uv、TypeScript 使用 pnpm，依赖安装使用项目配置的国内镜像。 |
| ADR-014 | CI 使用 Ruff、Pyright、pytest 和前端检查；PR/手动触发，`main` 通过分支保护复用检查结果。 |
| ADR-015/016 | PostgreSQL Job 租约是执行权事实来源；WorkerResult 先落库，再按结果结算 ACK、重试或死信。 |
| ADR-018/019 | API 只登记任务请求；编排层负责初始 Job/Outbox、检查点、幂等重放和恢复。 |
| ADR-020 | 静态工具失败保留结果工件并结构化结算失败；Task 阶段由实际 Job 推导。 |
| ADR-021 | 以持久化审计计划驱动适用基线，以 Finding 驱动复核和条件动态深审；`NO_FINDINGS` 须以必跑基线完整、覆盖度门禁通过和自动报告成功为前提。（2026-09-10 已接受，D-001） |
| ADR-022 | 空库通过 Web 一次性注册；模型连接与 API Key 由前端管理并持久化，API Key 不回显且传输依赖 HTTPS；基础设施与安全上限仍由部署配置注入。 |
| ADR-023 | Task 按 Job 的既有形状携带结构化失败：`tasks.failure` 列与 `Task`/`TaskStatusChangedPayload` 的 required 可空 `failure`，使编排层在没有 Job 时的失败原因可见。 |
| ADR-024 | 默认项目预算由服务端按已注册 ToolSpec 逐项最大值推导并校验下界；`binary-import` 数值校准到运行时实际值；请求预算统一经 `bounded_resource_budget` 按规格收敛。 |
| ADR-025 | 移除全部计算资源限制：预算保留为惰性簿记，不再有任何拒绝/收敛路径；沙箱安全隔离属性不变；模型上下文改为网关自动裁剪。（2026-09-11 项目负责人决策） |

## 8. 最近完成记录

| 日期 | 任务/变更 | 验证结果 | 后续工作 |
|---|---|---|---|
| 2026-09-11 | T38 报告下载与导出可读性修复（`fix/report-download`） | Docker Linux 临时测试容器内 `uv sync --all-packages --no-editable` 后，Ruff 通过；报告/API 定向测试 **36 passed**（含 PostgreSQL/Redis 集成，1 个 Starlette 弃用警告）；本次 Python 修改文件 Pyright 0 错误；Web `svelte-check` 0 错误 0 警告，Vite build 成功 | 标准 Dev Container 因 Docker Hub 鉴权网络超时未启动；仓库级 Windows Pyright 仅因未安装 `weasyprint` 报既有 `pdf.py` 缺失依赖；更新 API/Web 镜像后需补浏览器下载回归 |
| 2026-09-11 | T37 Markdown 快速路径 CI 修复（`ci/markdown-gate-move-gate`，PR #53 已合并入 `main`） | 首次实跑暴露（PR #50：`bad object`）与二次实跑暴露（PR #52：无凭据 fetch 失败）均登记于 Q-017；最终修复把 Markdown gate 移入全量克隆的 `change-scope` job，修复 PR 全量门禁通过；收尾 markdown-only PR（本条所属分支）的快速路径 CI 实跑为绿，Q-017 关闭 | 无 |
| 2026-09-10 | T36 Web 设置默认页与界面现代化改版（`feat/web-settings-first-modernization`，PR #49 已合并入 `main` `50fcbca`） | Dev Container 内 `pnpm --filter @vulnweaver/web typecheck` 0 错误 0 警告、`vite build` 成功；以临时 Mock API（契约同形数据，存系统临时目录不入库）+ 浏览器采集 17 张页面截图（桌面设置/项目/任务/认证三变体 + 移动端两张）经 judge 视觉验收全部通过；CI Python quality gate 通过 | 部署环境重建 Web 镜像后的真实浏览器回归待执行；远程分支 `origin/feat/web-settings-first-modernization` 保留未删（删远程分支需用户确认） |
| 2026-09-10 | Q-015/Q-016 修复（`fix/fresh-deploy-defaults`）：沙箱客户端超时默认值回归、工件卷属主竞争 | `docker compose config --quiet` 通过，依赖关系核对无误（api/analysis-worker/sandbox-runner → artifact-init，orchestrator 不受影响）；**删卷重建实测**：`down -v` 后 `up -d`，`artifact-init` exit 0、11 个容器全部 Up、`analysis-worker` 稳定（此前必崩溃循环）、工件卷 `.staging`/`.objects`/`.uploads` 属主均为 10001；Web `200`、`/health/ready` ready、`/api/auth/installation` `registration_open: true`（空库） | 无 |
| 2026-09-10 | Q-014 沙箱客户端超时默认值修正（`compose.yaml` / `.env.example`：60s → 660s） | 实时栈实测：60s 时 `binary-import` 在任务批准后精确 61s 失败（`ToolExecutionError`），沙箱容器在 Job 失败后仍在运行；置为 600s 后同一 PE 样本的 `import` Job `succeeded`，任务走完 `validating→analyzing→reporting→completed`（`result=partial`，产出 3 个工件版本） | 长耗时工具接入时按最长工具超时复核该默认值 |
| 2026-09-10 | Q-010~Q-013 修复（`fix/budget-and-orchestration-resilience`，基于 main `0098798`，已合并入 `main` `bf956b6`）：项目预算一致性、Task 失败可见性、队列韧性、proof/fuzz 预算方向 | 见下方验证记录；ADR-023/024 已新增；契约 `--check` 无漂移 | 由用户以浏览器走通「新建项目（默认预算）→ 提交 PE 任务」；已存在项目的预算需重建或修正（无更新端点）；是否推送 / 开 PR 待用户确认 |
| 2026-09-10 | T35 主分支全链路接线修复（`codex/fix-main-review`） | Linux Dev Container `pnpm run check`：437 passed、5 skipped、覆盖率 82.11%，Ruff/Pyright/TS/Svelte 0 错误；基础 Compose 重建成功，Web 首页与 Web→API 代理均 HTTP 200；新增二进制审计、自动报告、Harness 解包和复核历史回归 | 配置真实模型与固定 AFL/Proof 镜像后执行动态 E2E |
| 2026-09-10 | T32 自动投递接通（`feat/t32-fuzz-auto`，提交 `4ec38a0`） | `TaskAggregateSettlementHook` 新增 `FuzzDispatchScheduler` 协议与 fuzz 调度参数：复核结算后按 `exploit_validation_enabled` opt-in 对非 FALSE_POSITIVE 的 Finding 调度 fuzz（与 T31 同一门禁，动态执行语义一致）；`FuzzJobScheduler` 新增 `FuzzTargetResolver` 注入点与 `schedule_finding_in_transaction`，`schedule_in_transaction` 改为按 `task["artifact_version_ids"]` 绑定（`Task` 无 `input_refs` 字段，修正了错误的键访问）；analysis-worker 装配 `_fuzz_scheduler` 与 `_fuzz_target` 解析器（仅内存破坏/注入类别、锚定工件须属任务范围、无摘要则关闭）。新增 `test_fuzz_dispatch.py` 3 项（请求绑定新 Job 并通过契约校验、无目标时拒绝、无解析器时拒绝）。全量门禁：435 passed、5 skipped、覆盖率 82.24%，ruff/pyright 0 | 真实镜像 E2E；种子语料已按 D-002 决策维持默认，无剩余设计项 |
| 2026-09-10 | T32 Runner 摘要接口升级与 harness 编译管线（`feat/t32-fuzz-auto`） | `ToolRegistry.digests()` 由注册表派生摘要；Runner 新增 `GET /v1/tools` 且摘要端点一律由注册表作答，`SandboxRunnerClient` 支持 Bearer 与 `registered_tools()`，worker 经该端点发现 `afl-casr` 摘要；新增 `HarnessSource` 契约（修复原 `output_contract` 未注册导致真实网关 `KeyError`）、`harness-compile` 固定 profile、`HarnessCompiler`/`HarnessPipeline` 与 fuzz-tool `compile_harness`；`FuzzJobScheduler.schedule` 现构造真正合法的 `FuzzRequest`；crash 无法挂接 Finding 时返回结构化失败而非静默成功；修复 `persist_crash_evidence` 未排序时间戳与 `SandboxResult.status` 值比较。全量门禁：432 passed、5 skipped、覆盖率 82.28%，ruff/pyright 0，契约 --check 无漂移 | 契约中尚无 fuzz 目标/种子概念，自动投递需调用方提供 `FuzzTarget`；真实镜像编译+fuzz E2E 待部署 Runner 与登记摘要 |
| 2026-09-10 | T34 调用路径投影与报告消费（`feat/t32-fuzz-auto`） | `Finding.call_path` 契约 + `findings.call_path` 列（迁移 0018）+ Python/TS 绑定；`build_call_path_steps` 纯函数投影（仅 `call` 边、二进制指令节点经节点→函数映射解析、去重、上限 64）；静态投影与语义审计共享一次邻域读取填充；持久化读写对称；Markdown/HTML(→PDF)/SARIF 三处消费（SARIF 为 `codeFlows`）。修复 PairEdge 行映射未转换枚举导致 `is` 比较丢失全部调用边。全量门禁 432 passed、覆盖率 82.28%，ruff/pyright/TypeScript 全 0 | 真实报告 Job 端到端与独立 SARIF Schema 校验 |
| 2026-09-10 | T30 关键逻辑标定（PR #41） | 候选暂存、模型确认/否定合并及模型失败降级的 3 项新增测试通过；修复执行器与确认器签名/数据形状不匹配，恢复被 WIP 误覆盖的 orchestrator 公共导出；合并 T28 基线后 Linux Dev Container `pnpm run check`：385 passed、5 skipped、覆盖率 81.97%，ruff/pyright 与 svelte-check 0，契约 --check 无漂移；GitHub Quality Gate 通过后已合并 main | 已配置 PLANNING 模型和教学 ELF 完成真实 E2E |
| 2026-09-10 | CI 文档变更快速路径 | `.github/workflows/quality-gate.yml` 新增变更范围识别：仅 Markdown PR 只执行 `git diff --check`，代码/配置/工作流变更继续执行完整门禁；完整门禁改为按需启动 PostgreSQL/Redis；ADR-014 已同步 | 未在 GitHub Actions 运行器上实跑，提交 PR 后确认必需检查名称与分支保护配置兼容 |
| 2026-09-10 | T29 二进制伪代码审计接入（`feat/t29-binary-audit`） | `SemanticAuditFinding` 支持 address 锚定；审计遍历二进制 PAIR 函数（伪代码为上下文）；模型 finding 经 functions_at_address 锚定 BinaryLocation，幻觉地址丢弃；新增二进制锚定测试，全量 377 passed（ruff/pyright 0、契约 --check 无漂移） | 真实模型二进制端到端验收 |
| 2026-09-10 | T27 逆向规划接入 AgentLoop（`feat/t27-reverse-agent`） | ReversePlanningAgent 经 T25 循环规划 angr 定点目标并真实执行；规划失败降级固定管线；新增 4 项测试，Dev Container 全量 376 passed（ruff/pyright 0 错误） | 真实模型差异化规划验收归 E2E |
| 2026-09-10 | T31 漏洞自动利用智能体（`feat/t31-auto-exploit`） | 复核结算后自动投递 EXPLOIT Job；执行期模型生成脚本→安全红线校验→派生工件登记→沙箱执行→Poc 证据链；新增 `ExploitScript` 契约；测试 5 项新增，全量 370 passed（ruff/pyright 0 错误、契约 --check 无漂移） | 真实模型端到端验收（需 `PROOF_TOOL_IMAGE_DIGEST` 与产品模型配置） |
| 2026-09-10 | T33 函数工作台与智能体轨迹渲染（`feat/t33-workbench`） | 任务页新增函数列表→caller/callee 双列联动→伪代码代码视图的工作台，及 agent-runs 轨迹区；svelte-check 0 错误 0 警告、Vite 生产构建成功 | 真实二进制样本浏览器回归（依赖 T26 伪代码产出） |
| 2026-09-10 | ADR-021 NO_FINDINGS 聚合门禁（`feat/audit-plan-gate`） | 结算钩子从 Job 事实推导 AuditPlan（static_rules/semantic_function_audit），聚合结果为 NO_FINDINGS 且已配置语义审计调度器但必跑基线未完成时，阻断 COMPLETED 迁移并记录 `audit_plan_no_findings_blocked`（含缺失基线与覆盖度）；未配置审计调度器的降级部署保持原行为。新增测试 2 项，Dev Container 全量 365 passed | 真实模型 E2E；阻断时任务停留 ANALYZING 的运维语义随真实环境验收复核 |
| 2026-09-10 | T29 语义审计智能体源码侧（`feat/t29-semantic-audit`） | 新增 `semantic_audit` Job/契约/迁移 0017；静态基线结算后自动调度审计 Job，审计完成才调度独立复核（含模型发现候选）；模型 finding 强制锚定 PAIR 索引防幻觉；新增测试 4 项，Dev Container 全量 363 passed（ruff/pyright 0 错误、契约生成 --check 无漂移，PostgreSQL/Redis 集成环境实跑） | 二进制伪代码审计复用链路待 T26；真实模型 E2E 与 AuditPlan-NO_FINDINGS 聚合门禁待接入 |
| 2026-09-10 | T25 智能体规划执行框架（`feat/t25-agent-loop`） | 新增 `orchestrator/agent_loop.py` 通用规划—执行—观察循环与 `ActionPlanProposal` 公共契约（`06fdebb`、`9558375`，已 rebase 至最新 main）；15 个循环测试 + 2 个契约测试通过，覆盖循环推进、模型身份覆盖、策略拒绝回填与降级、轮次/token/deadline/步数预算终止、未配置立即降级、许可等待、失败步骤观察与观察截断；Ruff、Pyright 0 错误、契约生成 `--check` 无漂移、contracts tsc 通过 | 接入首个消费智能体（T27/T29/T31）后经真实任务验证 AgentRun 轨迹查询；合并前跑全量门禁 |
| 2026-09-10 | T24 Web 工作台布局与可读性优化 | 主内容限制在 1600px 可读轨道，项目与任务双栏按职责分配宽度；任务指标、Finding 操作区、事件载荷及窄屏断点完成；将原 9–12px 辅助文字提升至 11–14px；修复设置页复选框受整宽输入规则覆盖的错位；Web 镜像重建后首页 HTTP 200 | 可补一次真实浏览器多视口截图回归 |
| 2026-09-10 | P2 四语言真实模型端到端验收 | `.env` 中的 GLM 端点经 `/api/settings` 落库（api_key_configured=true，密钥不回显）；上传 C/C++/Python/Java 四个样本，四任务全部 completed：import 4 succeeded、source_analysis 6 succeeded、review 3 succeeded（模型 `review-model/glm-5.3-flash`），finding 按模型独立意见更新为 `unverifiable`（模型单独不能 confirm 的门禁生效）；Java 按设计无规则无候选。排查中修复：模型传输错误现在记录响应体（GLM 1210 max_tokens 限制可诊断） | 无剩余功能项 |
| 2026-09-10 | T16 DIE/Ghidra/UPX 工具镜像回放验收（`feat/t16-binary-tools`） | 新增 `apps/binary-tools` Dockerfile（DIE 3.21 deb + Ghidra 12.1.3 + openjdk-21-jdk + UPX）与 `vulnweaver-binary-entrypoint`（复用真实 binary-analysis 适配器）；`binary-analysis` 新增 `binary_tool_spec`/`binary_command_profile`，Runner 注册 BINARY_TOOLS_IMAGE_DIGEST profile 并为沙箱容器固定主机名解析。HTTP 回放：四工具全部 succeeded，binary-facts.json 25KB 入 CAS（含 Ghidra 真实伪代码）。修复 Ghidra 适配器项目目录未预创建缺陷。全量门禁 332 passed / 81.27% | P2 四语言真实模型端到端待模型接入 |
| 2026-09-10 | T19 AFL++/CASR 镜像回放验收（`feat/t19-afl-replay`） | 构建 `vulnweaver-afl-casr:fixed`（AFL++ 4.33c source-only + clang/gdb）与 `vulnweaver-fuzz-entrypoint`；修复 ASAN_OPTIONS symbolize=0、/tmp noexec（新增 /work exec tmpfs）、showmap 逐文件测量三个问题后，独立 Runner 完成：3000 次执行 30.5s、2 个 SIGABRT 崩溃入 manifest、afl-tmin 最小化输入摘要一致、覆盖率 100%；worker 侧 FuzzExecutionService 校验 FuzzResult succeeded（2 crash_ids）。全量门禁 332 passed / 81.34% | T16 DIE/Ghidra/angr 工具验收待真实环境 |

## 9. 验证记录

| 日期 | 验证项 | 结果 | 未覆盖范围 |
|---|---|---|---|
| 2026-09-11 | T38 真实模型 E2E（DeepSeek，重建全部镜像后） | 源码链路：9/9 Job 成功（import/静态×2/语义审计/复核×4/报告），模型自主发现 2 条固定规则外候选（CWE-95 eval、CWE-121 栈溢出），Markdown 报告含调用路径/证据链/复核引用；二进制链路：Ghidra 伪代码 17/27 函数进 PAIR、逆向规划智能体（planning-model 3 决策）、可读化 model_view_count=4、关键逻辑标定、报告；动态链路：fuzz Job 成功创建并进入沙箱编译修复回路，以结构化 `fuzz.harness_failed` PARTIAL 收尾（模型生成质量依赖，设计内） | auto-exploit（需 confirmed Finding）与 ELF 直接 fuzz 未触发；报告浏览器下载归 T22 里程碑 |
| 2026-09-11 | PR #57 CI Pyright 修复（`fix/task-event-stream`） | Linux 临时测试容器内持久化仓储定向回归 **16 passed**；目标文件 Pyright **0 errors**；Ruff **All checks passed**；`git diff --check` 通过 | 推送后等待 GitHub Actions 重新执行完整门禁 |
| 2026-09-11 | T39 任务事件契约兼容与部署镜像一致性修复（`fix/task-event-stream`） | Linux 容器定向回归 **50 passed**（PostgreSQL/Redis 集成实际执行），Ruff 通过；Compose `migrate` exit 0、alembic head 为 `0019_task_failure`、任务记录仍为 1；API `/health/live` 与 `/health/ready` 均 200；Orchestrator/Dispatcher/API/Analysis Worker/Sandbox Runner/Web 均稳定运行；Redis DB 0 已清理旧任务队列；运行中 Orchestrator 已确认包含 `failure` 字段的新版事件生成代码 | 当前 CLI 无可附着的用户浏览器会话，需用户刷新已打开的任务页确认视觉状态；未重新提交耗时分析任务 |
| 2026-09-10 | T36 前端门禁与视觉验收 | Dev Container（`vulnweaver-dev-1`）`pnpm --filter @vulnweaver/web typecheck`：0 错误 0 警告；`pnpm --filter @vulnweaver/web build` 成功（111 modules，CSS 29.06KB / JS 97.35KB gzip 后 6.56/34.81KB）。浏览器验证使用系统临时目录下的契约同形 Mock API（不进仓库）：17 张截图覆盖设置（含档位展开态）、项目（含新建表单）、项目详情、任务（指标/问题详情/工作台/Agent 轨迹）、认证三变体、移动端 390px 两页；judge 视觉验收 16/17 通过，唯一缺陷（移动端导航胶囊随项目数拉伸）修复后复核通过 | 真实部署栈（nginx 镜像 + api）下的浏览器回归未执行；Firefox/Safari 实机未验证；设置保存、Proof/Exploit 提交等写路径仅经 Mock 验证了前端交互形态 |
| 2026-09-10 | Q-010~Q-013 修复全量门禁与实时栈端到端（`fix/budget-and-orchestration-resilience`） | Dev Container（PostgreSQL/Redis 集成环境）`pnpm run check`：**451 passed、5 skipped、覆盖率 82.32%**，Ruff/Pyright 0 错误 0 警告、svelte-check 0 错误 0 警告、contracts tsc 通过、`generate_contracts.py --check` 无漂移；5 个跳过均为需 live Runner/Docker 的显式 opt-in。新增/扩展测试：`tests/api/test_budgets.py`（8 项：加载真实 `deploy/tool-specs` 断言默认预算覆盖全部规格、低于下界被拒并点名资源项、开启利用验证但无动态运行额度被拒、无规格目录时必填；并含 2 项真实 HTTP 端到端——未提供预算建项目 201 且预算覆盖全部规格、低于规格 422 `resource_budget_below_tool_requirements`）、`test_transient_queue_failure_keeps_the_orchestrator_polling`、`test_transient_queue_failure_keeps_the_worker_consuming`（两侧故障注入：`read_group` 前 2 次抛 `QueueUnavailable`，断言主循环退避后继续、进程不退出、读取次数 ≥3）、`test_policy_denial_fails_task_without_creating_job` 扩展（断言 `tasks.failure == result.failure` 且状态事件 payload 携带同一 failure）、`test_task_status_event_carries_a_structured_failure`（带 failure 通过、缺 failure 被契约拒绝）、`test_sandbox_request_budget_is_clamped_to_the_tool_spec`、`test_sandbox_budget_is_clamped_to_the_proof_tool_limits`。实时栈端到端：重建 api/web/dispatcher/orchestrator/analysis-worker 镜像并 `up -d`，`migrate` exit 0、alembic head `0019_task_failure`、`tasks.failure` jsonb 可空列就位；对实时库复跑诊断脚本，`_validate_inputs` / `_select_pipeline` / `_authorize_initial_job` 三节点全部通过（修复前在第三节点因 `resource_limit_exceeded` 被拒）；按 API 相同代码路径投递真实 PE 任务后，orchestrator 日志 `status=approved` 且创建 `job:2dd8262714…`（`kind=import`、`tool=binary-import`、`running`），任务进入 `validating`，日志新字段 `failure_code`/`failure_details` 生效 | 浏览器端到端（登录→新建项目→上传→任务→任务页展示失败原因）未执行，需用户会话；真实 Proof/Exploit 与 fuzz 的沙箱执行（需 confirmed Finding、固定镜像摘要与模型配置）未执行，其预算收敛由单元测试覆盖；`task.status_changed` 的 failure 渲染仅在 svelte-check 层面验证，无前端测试框架 |
| 2026-09-10 | T35 完整门禁与部署可达性 | Dev Container（PostgreSQL/Redis 集成环境）`pnpm run check`：**437 passed、5 skipped、覆盖率 82.11%**，Ruff/Pyright/TypeScript/Svelte 全绿；`docker compose -f compose.yaml config --quiet`、相关镜像重建通过；宿主访问 Web 200、经 Nginx 访问 `/api/auth/installation` 200、复核历史路由未登录返回预期 401 | 4 个 Proof HTTP 回放和 1 个 Docker runtime 测试为显式 opt-in；真实模型 Harness 与 AFL/Proof 动态执行仍需配置镜像摘要 |
| 2026-09-10 | PR #44 遗留验收收口（Dev Container `vulnweaver-t30-dev-1`，`feat/t32-fuzz-auto`） | PostgreSQL/Redis 集成环境下 `uv run --no-sync pytest -q --cov --cov-fail-under=80`：**435 passed、5 skipped、覆盖率 82.24%**；`uv run --no-sync ruff check .` 与 `./node_modules/.bin/pyright` 均 0 错误 0 警告；`generate_contracts.py --check` 无漂移；`pnpm run check:typescript`（tsc + svelte-check）0 错误。新增/扩展测试：`test_call_path.py`（8 项：anchor+caller/callee、非 call 边与自环忽略、二进制指令节点经节点→函数解析、外部未解析目标跳过、去重与上限、真实导入图投影）、`test_harness_pipeline.py`（9 项：固定 profile 请求形状、结构化诊断、未注册工具、bundle 确定性、修正后编译、预算耗尽恰好 3 次尝试、无效修正早停、未配置生成器、预算越界）、`test_runner_client.py`（3 项：本地 HTTP 真实 wire 上的 Bearer 认证与注册表发现）、`test_http.py`（+3 项 Runner 摘要端点/`/v1/tools` 列举/显式覆盖优先）、`test_fuzz_jobs.py`（+2 项调度器请求绑定与跨任务拒绝）、`test_fuzz_dispatch.py`（3 项：解析器产出目标时请求绑定新 Job 并通过 `FuzzRequest` 契约校验、无目标时拒绝、无解析器时不投递）、`test_job_executor.py`（+4 项 crash 挂接成功/未配置 sink 失败/缺 finding 失败/无崩溃成功）、报告三格式各新增调用路径断言 | 真实 AFL++/CASR 镜像的 harness 编译与受限 fuzz E2E、真实模型 harness 生成质量、真实报告 Job（PDF/SARIF）端到端与独立 SARIF Schema 校验；均需部署 Sandbox Runner、登记镜像摘要与配置 PLANNING 模型 |
| 2026-09-10 | 移除模型调用硬编码 token 上限（main 提交 `6e2452c`） | `key_logic.py` 删除 `max_output_tokens=4096`（走网关默认不限）；`readable_pseudocode.py` 的 `min(8192, budget)` 改为沿用 Job 资源预算（预算 0 视为不限，与 `auto_exploit.py` 一致）。沙箱资源限制与 Job 资源预算机制按安全红线保留。Dev Container（`vulnweaver-dev-1`）补跑 `pytest tests/binary_analysis -q`：32 passed（2 errors 为该容器 venv 缺 asyncpg 的环境问题，与本改动无关），受影响的 `test_critical_logic_confirm.py`、`test_readable_pseudocode_hook.py` 共 4 项全部通过；改动文件 ruff 通过 | 2 个 PostgreSQL 集成用例因 `vulnweaver-dev-1` 缺 asyncpg 未执行（t30 容器可跑，全量门禁已由后续 PR 覆盖） |
| 2026-09-10 | T30 分支全量门禁（worktree `feat/t30-key-logic`） | 合并 T28 基线后 Dev Container 内 `pnpm run check` 通过：ruff、pyright 0 errors/0 warnings，pytest 在 PostgreSQL/Redis 集成环境下 385 passed、5 skipped、覆盖率 81.97%，contracts TypeScript 与 svelte-check 0；`generate_contracts.py --check` 无漂移。5 个跳过均为需真实 Proof/Sandbox Runner 的 opt-in 回放 | 配置 PLANNING 模型和 `BINARY_TOOLS_IMAGE_DIGEST` 后的真实教学 ELF 端到端（候选→确认→PAIR API→前端） |
| 2026-09-10 | T29 二进制侧定向门禁（worktree `feat/t29-binary-audit`） | 新增二进制锚定测试（伪代码上下文进审计、address 锚定 BinaryLocation、幻觉地址丢弃）通过；全量 377 passed、ruff/pyright 0 错误、契约 --check 无漂移 | 真实模型 + 真实二进制样本端到端 |
| 2026-09-10 | T28 真实模型可读化回放（一次性容器，真实 Runner+真实模型） | gcc 编译的教学 ELF 经 Sandbox Runner binary-facts（binary-tools:t28 摘要）产出 18 函数/16 段真实 Ghidra 伪代码；混淆判定评估正常执行；DeepSeek 模型返回 4 个可读候选全部通过地址锚定校验（`readable-doc` 含原始摘录/确定性恢复/模型视图）。回放过程中修复并回归：`binary_command_profile` 空 target_addresses 不再产生空 argv 参数；hook 失败码与契约校验详情透出；提示词含小写 json 以兼容 DeepSeek json_object 模式；模型输入边界收紧为 4 函数/16KB 防止输出截断。定向测试/ruff/pyright 全绿 | 真实 OLLVM `fla` 编译产物验收（构建进行中） |
| 2026-09-10 | T28 定向门禁（Dev Container，`feat/t28-deobfuscation`） | `pytest tests/binary_analysis -q`：30 passed（含 PostgreSQL/Redis 集成环境实跑，指向 compose 服务名）；`ruff check .` 通过；`pyright` 0 错误；`generate_contracts.py --check` 无漂移 | 真实 OLLVM `fla` 编译产物验收（构建进行中）；真实模型可读化回放 |
| 2026-09-10 | T27 定向门禁（worktree `feat/t27-reverse-agent`） | 规划智能体 3 项测试（执行/降级/Sink 持久化）+ 执行器钩子集成测试（facts 传递、run_angr 真实执行、targets 进 generation_config）通过；全量 376 passed、ruff/pyright 0 错误 | 真实模型规划质量验收（需 AUDIT/PLANNING 模型配置） |
| 2026-09-10 | T31 定向门禁（worktree `feat/t31-auto-exploit`） | 新增 5 项测试（调度门禁×2、生成执行全链、危险脚本拒绝、钩子自动投递）通过；Dev Container 全量 370 passed（PG/Redis 集成实跑）、ruff/pyright 0 错误、契约 --check 无漂移 | 真实模型生成与真实沙箱镜像的端到端回放 |
| 2026-09-10 | T33 Web 定向门禁（worktree `feat/t33-workbench`） | Dev Container 内 `svelte-check` 0 错误 0 警告；`vite build` 成功（工作台/轨迹区进入产物 bundle） | 浏览器多视口回归与真实伪代码数据展示（依赖 T26） |
| 2026-09-10 | 审计计划门禁定向测试（worktree `feat/audit-plan-gate`） | 新增 2 项集成测试（阻断与放行/降级兼容）通过；Dev Container 全量 365 passed（PG/Redis 集成实跑）、ruff/pyright 0 错误 | 无 |
| 2026-09-10 | T29 定向门禁（worktree `feat/t29-semantic-audit`） | Dev Container：`ruff check .` 通过、`pyright` 0 错误、`generate_contracts.py --check` 无漂移；`pytest -q` 全量 363 passed、5 skipped（均为需 live Runner/Docker 的 opt-in 项），PostgreSQL/Redis 集成环境实跑 | 真实 AUDIT 模型端到端（需在产品设置配置模型后跑源码样本链路）；二进制伪代码审计依赖 T26 |
| 2026-09-10 | T25 定向门禁（worktree `feat/t25-agent-loop`，rebase 至 origin/main 后复跑） | Dev Container 内：`ruff check .` 通过；`pyright` 0 错误 0 警告；`pytest tests/orchestrator tests/tool_runtime tests/model_gateway tests/contracts`：56 passed（含 T25 循环测试 15 项与 ActionPlanProposal 契约测试 2 项）、29 skipped（一次性容器未启用 PostgreSQL 集成环境）；`generate_contracts.py --check` 无漂移；contracts `tsc --noEmit` 通过 | 全量套件与覆盖率门禁未在分支执行（合并前由全量门禁/CI 覆盖）；PostgreSQL/Redis 集成测试未跑 |
| 2026-09-10 | T24 Web 定向门禁 | 复选框修复后 Dev Container 内 `pnpm --filter @vulnweaver/web typecheck` 通过（0 错误、0 警告）；`pnpm --filter @vulnweaver/web build` 成功（111 modules transformed）；Web 镜像重建并替换运行容器，新 CSS 资源 `index-e2kade8Q.css`、首页 HTTP 200 | 未执行真实浏览器多视口截图回归 |
| 2026-09-10 | T26 完整定向验收 | Dev Container 内 Ruff 通过；`pytest -q tests/binary_analysis/test_binary_facts_adapter.py tests/pair/test_pair.py`：3 passed、1 skipped；Compose 内 PostgreSQL 下 `test_finding_evidence_review_and_annotation_api_are_auditable`：1 passed，覆盖 `/api/tasks/{task_id}/pair`、地址定位和 neighborhood 调用关系查询；binary-tools 与 analysis-worker 镜像已重建；真实数据库 Job→Worker→Runner→派生工件回放返回 `succeeded` |
| 2026-09-10 | P2 四语言端到端 | 真实数据库+真实模型：C/C++（CWE-120 strcpy）、Python（CWE-95 eval）候选 finding 均经独立复核（outcome=unverifiable，model=review-model/glm-5.3-flash），Java import/索引验证通过；全部门禁 333 passed / 81.26% | 利用链利用验证未执行（项目未开启 exploit_validation） |
| 2026-09-10 | T16 二进制工具链回放 | 独立 Sandbox Runner HTTP 回放（禁网/非 root/只读根）：DIE succeeded（compiler=GCC 14.2.0）、UPX succeeded（not_upx_packed）、objdump succeeded（21 函数/95 指令/34 xref）、Ghidra succeeded（19 函数/28 基本块/19 段伪代码导出 CAS）；修复 Ghidra 项目目录与沙箱主机名解析 | angr 动态执行未启用；PE 样本未单独回放 |
| 2026-09-10 | T19 真实镜像回放 | 禁网/非 root/只读根 fs/资源限制沙箱内 afl-fuzz 按 -E/-V 精确终止（100→16.4s，3000→30.5s）；crash-manifest 2 条 SIGABRT 带栈帧；minimized-inputs.tar 成员摘要与 manifest 一致；fuzz-summary coverage_percent=100.0；worker 侧解析 FuzzResult succeeded | 未接 CASR 原生二进制（聚类由服务端 stack_hash 完成）；长时程模糊测试未执行 |
| 2026-09-10 | T22 浏览器全链路 | 浏览器自动化走通登录→项目→任务→Finding 详情→报告下载；事件载荷可展开查看结构化 JSON；截图与 DOM 快照留证 | 真实上传新样本的完整分析链路（依赖真实 REVIEW 模型） |
| 2026-09-10 | T20/T21 完整队列链路回放 | 真实数据库：Proof Job API 202 → Dispatcher → Worker → HTTP Runner → CAS，Poc `completed/exploitable`；Markdown/SARIF/PDF 报告 Job succeeded 且 API 下载返回正确内容（`%PDF` 9.3KB、SARIF 2.1.0、Markdown Proof runs: 1） | 浏览器 UI 点击链路（T22）；报告重投曾因手工注入畸形流消息与消费者组偏移卡顿，已用 `XGROUP SETID 0` 恢复，属运维操作非代码缺陷 |
| 2026-09-10 | T23 定向门禁（隔离资源） | `codex-e2f0-*` 一次性容器、独立网络、tmpfs PostgreSQL：API/迁移/契约 34 passed（含 API Key 保留/清除）；Ruff、Pyright、Svelte、Vite 和 Compose 静态检查通过；测试资源已清除 | 未对既有运行栈执行迁移或浏览器 E2E |
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

1. T32 真实 E2E 前置（按序）：①构建包含 `compile_harness` 的 `vulnweaver-afl-casr:fixed`；②向 sandbox-runner 与 analysis-worker 配置同一 `AFL_CASR_IMAGE_DIGEST` 和令牌；③以授权源码教学样本验证有界源码摘录→Harness 生成/修复→沙箱编译→小型初始种子 Fuzz→崩溃证据挂接，并以 ELF 验证直接 Fuzz 路径。
2. T34 真实报告 Job 端到端：生成含调用路径的 Markdown/PDF/SARIF 并经 API 下载，SARIF 追加独立 Schema 校验（当前仅项目内 `validate_sarif` 信封校验）。
3. 为 T30 在产品设置配置 PLANNING 模型及 `BINARY_TOOLS_IMAGE_DIGEST`，以教学 ELF 运行候选→确认→PAIR API→前端展示的真实 E2E。
4. 完成 T28 真实 OLLVM `fla` 产物验收：复用 `ollvm-build` 容器中的 obfuscator-llvm llvm-4.0 构建产物，编译 `ollvm-style-flattened.c` 类似源码得到真实平坦化 ELF，经 Sandbox Runner binary-facts 回放验证混淆判定与可读伪代码派生工件。
5. 配置 AUDIT/PLANNING 等档位模型后，跑一次真实源码样本验证 T29 语义审计候选 Finding → 独立复核 → 报告链路；随后按真实模型验收 T27 规划差异化（加壳 vs 未加壳样本）与 T31 自动利用教学样本链路。
6. 里程碑全量回归：T20/T21/T22/T33 由「待验证」转「已完成」需在部署环境完成一次覆盖 Proof→报告→浏览器下载的全链路回归。
7. 仓库清理（可选，需确认）：移除 `vulnweaver-t30` worktree 与本地 `feat/t32-fuzz-auto` 分支；清理其它已合并本地分支（`docs/t30-merge-status` 等）与远程 `chore/skip-wip-ci`。
8. Q-010~Q-013（`bf956b6`/`291774d`）与 PR #45（设置页）、PR #46（模型网关）均已合并入 `main` 并推送；Q-015/Q-016 在 `fix/fresh-deploy-defaults` 上修复并验证。当前部署保留 PostgreSQL 中的 1 个任务及其工件；本次仅清理开发 Redis DB 0 的旧队列，不再执行数据库重置。若继续新建任务，仍需按页面提示配置复核模型（否则 `semantic_audit` 可能以 `model_budget_exhausted` 失败、任务只能到 `partial`）。
9. T38 部署回归：更新 API/Web 镜像后确认 Markdown/PDF/SARIF 下载文件名分别带 `.md`、`.pdf`、`.sarif`，并确认失败报告在任务页显示结构化原因。
10. T39 修复后：刷新已打开的任务页；若浏览器仍保留旧错误横幅，关闭后重新打开该任务页即可重新建立事件流。

更新时间：2026-09-11（Asia/Shanghai）
