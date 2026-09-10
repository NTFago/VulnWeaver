# Agent 动态交接台账

> 本文件只维护当前进度、问题、阻碍、决策摘要、验证结果和下一步。稳定开发规则见 `AGENTS.md`；架构依据为 `系统架构设计与技术选型.md`，实现任务依据为 `系统实现模块拆分.md`。

## 1. 项目目标

构建面向已授权源码仓库和 x86/x64 ELF/PE 二进制的软件漏洞挖掘系统。系统通过智能体编排静态分析、逆向分析、模糊测试、独立复核、最小复现和可选利用验证，输出可追溯的 Finding、证据链和报告。

## 2. 当前工程状态

- **项目名称**：VulnWeaver（漏洞织鉴）
- **当前日期**：2026-09-10（Asia/Shanghai）
- **当前阶段**：对照《2026 网络空间安全课程设计》要求完成差距分析（Q-009）：T01-T24 按此前裁剪范围全部完成，但课设核心要求——多智能体自主协作、二进制逆向自主规划与伪代码漏洞检测、关键逻辑标定、自动利用生成、证据链报告——尚未实现。已建立补齐任务包 T25-T34（定义见第 3.1 节，均未开始）。
- **当前分支**：`main`。
- **当前负责人**：Codex（T01-T24）；T25-T34 待认领。P2 四语言端到端使用 `.env` 中的 GLM（bigmodel.cn）端点经 T23 产品设置落库后执行；注意 GLM 限制单请求 `max_tokens ≤ 131072`，任务预算 `max_model_tokens` 需 ≤ 该值。
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
| T25 智能体规划执行框架 | 未开始 | 待认领 | — | 通用“规划—执行—观察”Agent 循环：LLM 输出结构化 ActionPlan → Policy Engine 校验 → 工具/Job 调度 → 结果回填 → 多步迭代；决策轨迹写 AgentRun；步数/token/时间预算与无模型结构化降级（定义见 3.1） | 2026-09-10 |
| T26 二进制主管线收口（Ghidra 默认可用） | 未开始 | 待认领 | — | 默认部署启用 Ghidra 反编译（worker 镜像安装或接通 binary-tools 死路径，二选一记录决策）；伪代码/函数/调用关系入 PAIR 并经 API 可查（定义见 3.1） | 2026-09-10 |
| T27 逆向分析智能体与混淆特征识别 | 进行中 | Codex | 已新增控制流扁平化启发式识别器，按函数输出 dispatcher、间接跳转、分数和可解释理由；尚未接入 T25 规划循环 | 接入分析结果、模型规划与固定管线降级 | 2026-09-10 |
| T28 解混淆与可读伪代码生成 | 进行中 | Codex | 修复 angr helper 参数数量校验与 usage 文案；尚未完成真实 angr/解混淆链路 | 控制流平坦化恢复、可读伪代码派生工件和真实环境验收 | 2026-09-10 |
| T29 语义审计智能体（源码+二进制） | 未开始 | 待认领 | — | 落地 ADR-021 AuditPlan 必跑基线与覆盖度门禁；LLM 按函数邻域（源码）/伪代码+调用邻域（二进制）语义审计产出候选 Finding，进入既有独立复核链路，打通二进制端到端（定义见 3.1） | 2026-09-10 |
| T30 关键逻辑标定 | 进行中 | Codex | 新增基于函数名、导入表和字符串的认证/加密/注册候选发现器，返回分数与证据关键词；已在 Dev Container 通过定向测试 | 接入 PAIR 持久化、LLM 确认、API 与前端展示 | 2026-09-10 |
| T31 漏洞自动利用智能体 | 未开始 | 待认领 | — | 对 confirmed 且开启利用验证的 Finding，由模型自动生成 PoC/利用脚本并经 Sandbox Runner 验证（替代手工 script_ref），脚本与结果作为证据链落库（定义见 3.1） | 2026-09-10 |
| T32 模糊测试接入自动链路与 harness 生成 | 进行中 | Codex | 新增不执行命令的有界 harness 编译—诊断—修正循环抽象，支持结构化诊断与预算耗尽结果；Dev Container 定向测试待提交前复核 | 接入 LLM harness 生成、Sandbox 编译执行、fuzz Job 自动调度和 Finding 证据挂接 | 2026-09-10 |
| T33 前端逆向工作台与人工复核 | 进行中 | Codex | API 新增受限函数调用邻域端点；Finding 详情已加入人工复核意见与标注提交入口，Web API 客户端已接入 | 前端函数浏览/高亮、伪代码联动与浏览器回归验证 | 2026-09-10 |
| T34 报告证据链写实 | 进行中 | Codex | Markdown/HTML(PDF源) 增加证据与复核引用、严重等级/状态；SARIF 增加 fixes 修复建议 | 二进制地址/调用路径/工件摘要明细及真实 PDF/SARIF Schema 验收 | 2026-09-10 |

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
| Q-009 | 对照课设要求差距分析（2026-09-10，只读核查确认）：①全系统唯一 LLM 生产调用是独立复核，无自主规划智能体，ActionPlan/LangGraph 均为固定管线；②二进制主管线默认无 Ghidra（env 空且 worker 镜像未装），binary-tools 沙箱工具为死路径，二进制任务不产生 Finding；③无关键逻辑标定、无混淆识别/解混淆（`angr_helper.py:13` argv 校验 `!=7` 与实际 10 参数不符，启用即失败）；④模糊测试未接入自动管线、无 harness 生成；⑤利用需手工提供 script_ref；⑥前端无调用链/伪代码/Agent 轨迹/人工复核标注展示；⑦报告证据链仅计数，PDF 无严重等级 | 课设题目核心要求（多智能体协作、二进制逆向自主规划、伪代码漏洞检测、关键逻辑标定、自动利用、证据链报告）未覆盖，T01-T24 的“全部完成”是对裁剪后范围而言 | 已建立补齐任务包 T25-T34（定义见 3.1），按 P0（T25/T26/T27/T29）→P1（T28/T30/T31/T33/T34）→P2（T32）顺序实施 | 待处理 | 待认领 |

## 5. 当前阻碍点

当前无阻碍。T16/T18/T19/T20/T21/T22 的未完成项属于待验证工作，不应标记为阻碍。

## 6. 待确认事项

| ID | 待确认事项 | 推荐默认值 | 决策人 | 状态 |
|---|---|---|---|---|
| D-001 | ADR-021 是否采用“审计计划驱动的必跑基线 + Finding 驱动的条件深审”，并由计划完整性约束 `NO_FINDINGS` | 采用；先完成计划、覆盖度、自动 Markdown 和结算完整性，再扩展检测面与动态分支 | 项目负责人 | 已接受（2026-09-10） |

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

## 8. 最近完成记录

| 日期 | 任务/变更 | 验证结果 | 后续工作 |
|---|---|---|---|
| 2026-09-10 | T24 Web 工作台布局与可读性优化 | 主内容限制在 1600px 可读轨道，项目与任务双栏按职责分配宽度；任务指标、Finding 操作区、事件载荷及窄屏断点完成；将原 9–12px 辅助文字提升至 11–14px；修复设置页复选框受整宽输入规则覆盖的错位；Web 镜像重建后首页 HTTP 200 | 可补一次真实浏览器多视口截图回归 |
| 2026-09-10 | P2 四语言真实模型端到端验收 | `.env` 中的 GLM 端点经 `/api/settings` 落库（api_key_configured=true，密钥不回显）；上传 C/C++/Python/Java 四个样本，四任务全部 completed：import 4 succeeded、source_analysis 6 succeeded、review 3 succeeded（模型 `review-model/glm-5.3-flash`），finding 按模型独立意见更新为 `unverifiable`（模型单独不能 confirm 的门禁生效）；Java 按设计无规则无候选。排查中修复：模型传输错误现在记录响应体（GLM 1210 max_tokens 限制可诊断） | 无剩余功能项 |
| 2026-09-10 | T16 DIE/Ghidra/UPX 工具镜像回放验收（`feat/t16-binary-tools`） | 新增 `apps/binary-tools` Dockerfile（DIE 3.21 deb + Ghidra 12.1.3 + openjdk-21-jdk + UPX）与 `vulnweaver-binary-entrypoint`（复用真实 binary-analysis 适配器）；`binary-analysis` 新增 `binary_tool_spec`/`binary_command_profile`，Runner 注册 BINARY_TOOLS_IMAGE_DIGEST profile 并为沙箱容器固定主机名解析。HTTP 回放：四工具全部 succeeded，binary-facts.json 25KB 入 CAS（含 Ghidra 真实伪代码）。修复 Ghidra 适配器项目目录未预创建缺陷。全量门禁 332 passed / 81.27% | P2 四语言真实模型端到端待模型接入 |
| 2026-09-10 | T19 AFL++/CASR 镜像回放验收（`feat/t19-afl-replay`） | 构建 `vulnweaver-afl-casr:fixed`（AFL++ 4.33c source-only + clang/gdb）与 `vulnweaver-fuzz-entrypoint`；修复 ASAN_OPTIONS symbolize=0、/tmp noexec（新增 /work exec tmpfs）、showmap 逐文件测量三个问题后，独立 Runner 完成：3000 次执行 30.5s、2 个 SIGABRT 崩溃入 manifest、afl-tmin 最小化输入摘要一致、覆盖率 100%；worker 侧 FuzzExecutionService 校验 FuzzResult succeeded（2 crash_ids）。全量门禁 332 passed / 81.34% | T16 DIE/Ghidra/angr 工具验收待真实环境 |
| 2026-09-10 | T22 浏览器全链路验收与最终验收报告 | 重建 web 镜像后经浏览器自动化验证：登录、任务页可观测性（状态汇总/Jobs/事件载荷展开）、Finding 详情（复现记录 EXPLOITABLE、Proof/Exploit 入口）、报告下载点击触发下载；验收报告归档 `code/docs/progress/2026-09-10-acceptance-report.md` | 里程碑回归与 T16/T18/T19/P2 真实环境验收 |
| 2026-09-10 | T20 全链路 + T21 真实数据库报告回放 | 重建 analysis-worker/api/migrate 镜像（补 `vulnweaver-proof` 依赖、WeasyPrint 系统库），配 `SANDBOX_RUNNER_URL` 后：API 提交 Proof Job 经 Dispatcher/Worker/Runner 全链路成功（Poc `completed/exploitable`）；Markdown/SARIF/PDF 报告 Job 真实数据库回放成功并可经 API 下载；修复报告渲染未纳入 Poc 的问题（Markdown/HTML 现显示 Proof runs）。Dev Container 门禁 329 passed | T22 浏览器全链路收口 |
| 2026-09-10 | T23 Web 首次注册与产品设置 | 独立网络与 tmpfs PostgreSQL 中 API/迁移/契约 34 passed；Ruff、Pyright、Svelte、Vite build、Compose config 通过；未触碰既有 VulnWeaver 容器/网络/卷 | 合并后在独立 TLS 部署完成浏览器首次启动 E2E |
| 2026-09-10 | ADR-021 评审结论登记 | PR #17 合并入 `main`（`b704814`）；项目负责人批准 D-001，ADR-021 状态改为已接受，勾选评审结论并同步 `DEVELOPMENT_STATUS.md`；纯文档变更 | 按ADR-021实施顺序启动 AuditPlan/覆盖度/结算门禁设计任务 |
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
| 2026-09-10 | T24 Web 定向门禁 | 复选框修复后 Dev Container 内 `pnpm --filter @vulnweaver/web typecheck` 通过（0 错误、0 警告）；`pnpm --filter @vulnweaver/web build` 成功（111 modules transformed）；Web 镜像重建并替换运行容器，新 CSS 资源 `index-e2kade8Q.css`、首页 HTTP 200 | 未执行真实浏览器多视口截图回归 |
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

1. 认领 T25 智能体规划执行框架（P0 地基，T27/T31/T32 依赖其循环与降级语义），按 3.1 验收标准实现并测试。
2. 并行认领 T26 二进制主管线收口：为 analysis-worker 镜像内置 Ghidra 或接通 binary-tools 沙箱路径（二选一，在 ADR/台账记录决策），使 ELF 教学样本伪代码经 `GET /api/tasks/{id}/pair` 可查。
3. T29 语义审计智能体（源码侧可先行，不依赖 T25/T26）：落地 ADR-021 AuditPlan 必跑基线，使 LLM 产出候选 Finding；二进制侧在 T26 完成后打通端到端。
4. 其余按 T27 → T30 → T28 → T33 → T34 → T31 → T32 推进；每个任务包完成前逐项核对 3.1 验收标准与对应模块（M01/M07/M10/M11/M13/M14/M15/M16）验收标准。

更新时间：2026-09-10（Asia/Shanghai）
