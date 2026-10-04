# DEVELOPMENT STATUS

> 轻量交接台账。稳定规则与安全红线见 `AGENTS.md`；已完成任务（T45–T52 等）的实现明细与 2026-10-01 前的门禁记录已裁撤，见 Git 历史、PR 与 `code/docs/progress/`。

更新时间：2026-10-04（Asia/Shanghai）

## 当前焦点

2026-10-04 RF 修复轮（分支 `feat/realworld-acceptance-samples @ 1ca1d20`）：RP 修复复审的 RF-01～02 已修复并部署。①RF-01：分页模型调用失败时 `_AuditError` 现在原样携带网关失败的结构化 `kind`/`retryable`/`message` 到 WorkerResult——可重试传输失败（超时、HTTP 408/429/5xx → `ModelTransportError` retryable=True）不再被 `_AuditError` 默认值抹成终态，断点在下一 attempt 被消费；新增 Worker 结算级回归：第 0 页成功、第 1 页传输失败、Worker 自动重入队、attempt 2 从断点恢复只重跑第 1 页（第 0 页从未重发，页拆分断言锁定）。②RF-02：Worker 时钟测试改为在第 0 页完成之后（第 3 次时钟调用）触发截止，并断言 attempt 1 保存 `next_page=1` 断点、attempt 2 只执行剩余页、最终断点 completed。新并行门禁完整输出：**761 passed / 7 skipped、覆盖率 81.10%、192.1s**；重建 7 个镜像并重启，migrate exit 0、API ready、Web 200；真实 Runner 验收 **6 passed**。至此"分页回退审计可恢复"对本地截止与模型传输故障两类中断均经 Worker 结算级验证。

2026-10-04 RP 修复复审（`feat/realworld-acceptance-samples @ 69cfba2`）：RP-01～03 的主要代码路径已修复，Linux `dev` 容器定向测试 **8 passed**。仍发现 RF-01/P1：分页模型传输失败返回的可重试标志被 `_AuditError` 默认值抹掉，Worker 终结 Job，断点无法续跑；RF-02/P2：新增 Worker 测试在第一页之前触发截止，未验证从已完成页继续。详见 [`code/docs/code-review-2026-10-04-paged-audit-followup.md`](code/docs/code-review-2026-10-04-paged-audit-followup.md)。本轮只读产品代码，未独立运行全量门禁或部署。

2026-10-04 RP 修复轮（分支 `feat/realworld-acceptance-samples @ 69cfba2`）：分页审计续审的 RP-01～03 已修复并部署。①RP-01：分页截止超时改为可重试 TIMEOUT（结构化失败带"覆盖不完整、下次 attempt 从断点恢复"消息），新增 **Worker 结算级**测试驱动真实 `ReliableWorker`——attempt 1 在第一页前截止、Worker 记录失败并重新入队、attempt 2 从第 0 页重跑直至全覆盖（续页断言仍缺）（`tests/worker/test_worker_semantic_audit_retry.py`）；②RP-02：断点绑定页大小与有序 (version, function) 索引摘要，页大小或索引变化的续跑丢弃旧断点并全量重审（绝不把未审计函数计为 complete），聚合覆盖改用断点自身绑定的页大小/页数（回归：页大小变更后重审全部 4 函数、coverage 完整为真）；③RP-03：分页证据身份加入页片段（同一问题跨页产生两条证据、各自绑定片段 report_ref/digest，链接到同一稳定 Finding），页内重复候选按证据 ID 去重（回归：跨页重复候选不再 EntityConflict）。新并行门禁完整输出：**760 passed / 7 skipped、覆盖率 81.07%、184.5s**；重建 7 个镜像并重启，migrate exit 0、API ready、Web 200；真实 Runner 验收 **6 passed**。

2026-10-04 分页语义审计续审（`feat/realworld-acceptance-samples @ 9251e79`，只读产品代码）：发现 RP-01/P1：截止超时被标 `retryable=False`，Worker 不会消费已保存断点；RP-02/P1：断点未绑定页大小/索引身份，变更页大小后可能把未审计函数汇总为 `complete=true`；RP-03/P2：跨页重复候选生成相同证据 ID、不同片段引用，触发 `EntityConflict` 中断审计。详见 [`code/docs/code-review-2026-10-04-paged-audit.md`](code/docs/code-review-2026-10-04-paged-audit.md)。Linux `dev` 容器定向分页测试 **5 passed**；该测试未覆盖 Worker 结算、断点配置变化或跨页重复候选。本轮未修改产品代码或部署，未跑全量门禁。

2026-10-04 RG 修复轮（分支 `feat/realworld-acceptance-samples @ add7676`）：复审重开的 RG-01～03 已修复并部署。①RG-01/02：确认链诚实降级——`reviews.py` 不再从差分 POC 证据派生任何注入/鉴权确认事实（同进程 sink 观测可被 `os._exit(20)` 伪造或 `sys.setprofile(None)` 致盲，且 sink 触发≠输入传播），`sink_reached`/`protections_observed` 仅作诊断，注入/鉴权 Finding 保持候选；ADR-036 记录"同进程解释器内无法构造目标不可伪造观测通道"的结论与解除条件（P0.5 crash oracle 走 OS wait status、传播判据见 oracle 提案 §5）。②RG-03：AST 保护扫描按完整限定路径解析（镜像运行时的模块全局→类属性语义），同名歧义/条件分支重复定义/别名赋值一律拒绝扫描；`callable_resolved` 锚点记录完整路径。③新增 opt-in Runner 负例（`tests/proof/test_target_bound_injection_negatives.py`）：exit-20 伪装与常量 sink 两例固定"伪造可落地、确认不可达"，profiler 致盲固定保守方向（无 reach 声明）。新并行门禁完整输出：**757 passed / 7 skipped、覆盖率 81.05%、177.5s**，Ruff/Pyright/contracts/TypeScript/Web 构建通过；重建 7 个镜像并重启，migrate exit 0、API ready、Web 200；真实 Runner 验收（含 3 个新负例）**6 passed**。共享 CAS 卷在 runner 建新目录后需再次 `chmod -R a+rwX`（已记入经验教训）。

2026-10-04 本轮复审（分支 `feat/realworld-acceptance-samples`）：**注入确认链重新标为待修复**（已由上段修复）。RG-01/P0：目标代码与 `sys.setprofile` 同进程，能用 `os._exit(20)` 伪装父进程信任的 sink 退出码，或关闭 profiler 漏报；RG-02/P0：真实 sink 调用与输入差分也不证明 crafted 输入进入 sink；RG-03/P1：AST 按短名选函数，可能把另一个类的同名方法当成执行目标扫描，非空 anchor 条件无法发现错位。详见 [`code/docs/code-review-2026-10-04-gates.md`](code/docs/code-review-2026-10-04-gates.md)。本轮只改质量门禁：并行且保留完整带来源日志，补 contracts 漂移/Web 构建，强制测当前源码，覆盖率补 `proof`/`reporting` 并排除生成声明。Linux dev 容器完整门禁 **753 passed / 4 skipped，覆盖率 81.18%，190.7 秒**；Ruff、Pyright、contracts、TypeScript/Web 构建均通过。未修改产品确认逻辑、未部署；在 RG-01～03 消除前不把注入 Finding 的既有证据链视为可信闭环。

2026-10-04 上一轮修复记录（分支 `feat/realworld-acceptance-samples @ 3902c4e`，注入结论由本轮 RG-01～03 修正）：RA-01～RA-05 当时均按既有回归关闭并部署。①注入 reach 由 target-worker 的 `sys.setprofile` 观测经退出码 20 传给 entrypoint；该退出码现发现可由目标伪装。②鉴权确认事实派生移除，Finding 保持候选。③约束提取严格 path/line/address 匹配。④分页汇总逐片段重验摘要并读取嵌套 report。⑤行为判定从运行摘要重算差分。历史门禁 **753 passed / 4 skipped**、Ruff/Pyright/contracts/TypeScript 通过；当时重建 7 个镜像并重启，migrate exit 0、API ready、Web 200；真实 Runner 验收 **3 passed**，但未覆盖本轮 RG 负例。

2026-10-04 最新分支只读审计（`feat/realworld-acceptance-samples @ bce0a24`）：发现 CR-04 的注入和鉴权证据映射仍可把普通输入差分提升为确认条件；另有源文件约束匹配错误、分页汇总报告丢失 findings、观测一致性校验接受相同摘要却声称差分。详见下方"本轮审计待修复"。本轮仅运行定向测试与无害契约级复现，未修改程序代码或部署。

2026-10-04 已完成 `main @ f5bc37e` 部署。针对 `2757f35` 的复核发现 bundle 精确成员检查漏掉 manifest，以及目标代码和报告器共进程可伪造 observation；现已修复为入口严格要求 manifest、目标每轮在一次性子进程运行并设 30 秒超时、worker 依据 CAS bundle manifest 交叉核对 observation。同期修复 callable 来源校验、报告自洽与 bundle 全字段核对、PoC/evidence 原子幂等写入、TIMEOUT/ENVIRONMENT 重试，以及 agentic Finding 报告必填 constraint。

2026-10-04 第二轮（分支 `feat/realworld-acceptance-samples`，提交 `a7baad8`/`1fb5b40`/`92bb0d7`）：审查清单剩余缺陷 CR-04 剩余、CR-05、CR-06、CR-07、CR-08 已实现并部署。要点：①CR-08 聚合逐集合截断账目（`BinaryCoverage` 契约）进入 result 文档、规划 facts 与 agent `artifact_facts`/`analysis_baseline`，imports 独立 `max_imports` 上限；②CR-06 回退审计按页（64 函数/页）调用并逐页投影+checkpoint 续跑（deadline 8h 兜底），消除 256 函数截断；读取证明键改为 `(version_id, path, line)`，跨版本同路径不再互相授权；③CR-07 `PairRepository.neighborhood` 下推递归 CTE（2000 函数图 402ms→54ms、6000 函数 110ms，基准脚本入库），审计入口 `has_functions` 廉价探针消除双重全量装载；④CR-04 剩余：entrypoint 逐轮捕获有界输出并摘要，新增 `verified_behavior` 判定（crafted≠control 且重放一致），worker 依据自校验 observation 派生 STRONG `POC_VERIFICATION_RESULT`（注入 sink_reached；鉴权 behavior_difference+constraint_digest 绑定审核期约束 SHA-256），gate 恢复 markers 白名单并把约束绑定映射为 `constraint_analysis`。全量 Python 门禁 735 passed / 4 skipped、覆盖率 81.79%；真实 Runner 正反例 3 passed；受影响 9 个镜像已重建、栈已重启、migrate exit 0（0024）、API ready、Web 200。

2026-10-04 第三轮（同分支，提交 `708a4f4`）：CR-04 收尾。注入类 `protection_analysis` 独立判据落地——控制面 AST 保护枚举器对 bundle 摘要锁定的目标源码确定性枚举危险 sink/守卫/校验/净化构造，marker 经 worker 注入类 STRONG 证据，gate 全链确认注入 Finding 回归通过；独立崩溃/利用 oracle 立项评估完成（建议 P0.5 解释器信号 `crash_kind`）。全量 Python 门禁 **742 passed / 4 skipped**（覆盖率 81.8%，此前一轮 735+1 项并行偶发 error 复跑确认稳定）；Ruff/Pyright/contracts/TypeScript 门禁通过；重建 proof-tool/api/dispatcher/orchestrator/analysis-worker/sandbox-runner/web 镜像并重启，migrate exit 0、`/health/ready` ready、Web 200、真实 Runner 验收 3 passed。详见 [`code/docs/code-review-2026-10-03.md`](code/docs/code-review-2026-10-03.md) 与 [`code/docs/oracle-proposal-2026-10-04.md`](code/docs/oracle-proposal-2026-10-04.md)。

系统定位为**面向真实世界样本的长线漏洞挖掘智能体系统**。逐项审查缺陷代码证据见 [`code/docs/code-review-2026-10-03.md`](code/docs/code-review-2026-10-03.md)。agent 主导挖掘和长线调查仍是产品方向，但不能用 Job 成功或历史测试通过替代漏洞验证。

当前目标绑定验证的**能力边界**：本地分支将目标范围收窄为可从 UTF-8 Python 源文件导入并调用的函数；C/C++ 原项目构建/链接绑定（BuildProfile、完整 TargetSnapshot）属 P1，sanitizer 崩溃 oracle 随该轨立项；内存破坏类 Finding 在纯 Python 目标边界内结构性不可确认（无解释器信号来源，见 oracle 评估 §1），保持候选是正确行为而非缺陷。

## 当前阻碍与审查缺陷（2026-10-03 清单，2026-10-04 状态）

| 编号 | 状态 | 影响与解除条件 |
|---|---|---|
| RG-01～03 / P0/P1 | 已修复（`add7676`，注入确认保持关闭） | RG-01/02：同进程 sink 观测的退出码可伪造/可致盲且 sink 触发≠输入传播——确认事实派生整体撤除（`reviews.py` 仅余 `minimal_reproduction`），marker 降为诊断；ADR-036 记录观测边界结论与解除条件（P0.5 crash oracle 走 OS wait status、传播判据提案）。RG-03：AST 扫描按完整限定路径解析并拒绝歧义（同名/条件重复/别名）。Runner 负例固定"伪造可落地、确认不可达"边界与致盲保守方向。 |
| CR-01、CR-02 / P0 | 已完成（P0 范围） | 执行输入与元数据分离为 bundle 成员并逐成员摘要校验；原目标以只读成员绑定（TargetBinding：artifact/version/digest）；`SandboxStatus` 成功不再产生任何漏洞结论，结论仅由可信入口的 `VerificationObservation` 决定。真实 Runner 正反例验收通过（`tests/proof/test_target_bound_runner.py`，opt-in）。C/C++ 目标构建绑定转 P1。 |
| CR-03 / P1 | 已完成 | 生成的受限调用描述与 ExecutionBundle 均为独立 DERIVED 工件（bundle 父版本指向原样本版本）。数据库回归确认原样本 `current_version_id` 不变。 |
| CR-04 / P1 | 确认链已按观测边界关闭（注入/鉴权均候选）；判据立项待提案 | RG-01～03 修复后，注入与鉴权确认事实均不从差分 POC 证据派生（同进程观测可伪造/可致盲，sink 触发≠输入传播），`sink_reached`/`protections_observed`/`constraint_digest` 仅作诊断 marker；AST 扫描按完整限定路径解析并拒绝歧义（RG-03）。Runner 负例（exit 20 伪装、常量 sink、profiler 致盲）固定"伪造可落地、确认不可达"。解除条件：P0.5 crash oracle（解释器信号经 OS wait status，`os._exit` 不可伪造）与可执行传播/约束判据（oracle 提案 §5）按 ADR 立项后另行恢复派生。独立崩溃/利用 oracle 评估见 [`code/docs/oracle-proposal-2026-10-04.md`](code/docs/oracle-proposal-2026-10-04.md)。 |
| CR-05 / P1 | 已完成 | 必填 constraint + `_issue_identity` 归一指纹（NFKC/空白/大小写）进入 evidence 身份；同任务 CWE+精确位置稳定去重；同函数不同源码行回归通过；新增同函数双地址（二进制）回归通过。 |
| CR-06 / P1 | 已完成 | 回退审计分页化（64 函数/页）+ 逐页投影与 checkpoint 续跑，8h deadline 兜底（TIMEOUT 可重试），消除 256 函数截断；汇总报告逐片段重验 CAS 摘要并合并嵌套 findings，缺失/篡改即硬失败（RA-04 修复）。源码搜索按唯一文件计数（此前已修）；finding-report 读取证明键为 `(version_id, path, line)`，跨版本同路径读取不再互相授权（回归 `tests/orchestrator/test_code_audit.py`）。 |
| CR-07 / P1 | 已完成（本轮量化+优化） | 基准：2000 函数图 neighborhood depth1 402ms→**54ms**，6000 函数 **110ms**（`code/scripts/benchmark_pair_neighborhood.py`）。邻域下推递归 CTE，只取到达子图；审计入口以 `has_functions` 探针替代全量装载，agent 成功路径零重复装载、回退路径单次装载。`pair.neighborhood` 全图入 Python 的旧实现已移除；`agent_runs.save_progress` 写放大与 ProjectView N+1 仍是候选项（见下一步 8）。 |
| CR-08 / P2 | 已完成 | 聚合 merge 逐集合记录 offered/retained/limit/截断原因（去重不计截断），strings 提取报告 offered；覆盖信息进入 `BinaryAnalysisResult.coverage`、规划 facts `coverage_incomplete`、agent `artifact_facts` summary 与 `analysis_baseline.truncated_collections`；imports 独立 `max_imports`（默认不变）。超限样本回归见 `tests/binary_analysis/test_coverage.py`。 |
| CR-09–11 / P0 | 已修复、Runner 验收并部署 | 目标调用移入每轮隔离子进程，supervisor 独立写报告；bundle/observation 绑定 Finding 与目标版本，入口和 worker 交叉核对摘要。Runner 正反例 3 passed，镜像重建且应用容器已重启。 |
| 复核 P0-1/2、P1-1/2/3/4/5 | 已修复并通过全量门禁/定向 Runner | manifest 严格成员检查包含 manifest 本身；导入模块 callable 拒绝；观察计数、运行角色、bundle 成员和 verdict 自洽；目标调用单轮超时；PoC 与 evidence 同事务、生成物按 job 幂等复用，TIMEOUT/ENVIRONMENT 按策略重试；agentic finding-report 要求 constraint，Finding 身份以 CWE+精确位置稳定去重。 |
| 复核 P1-6 | 已修复 | 可重复目标异常结果为 `INCONCLUSIVE`，观测只作为 `SUPPORTING` evidence；`FindingReviewGate` 不从此 observation 推导崩溃、可控输入或匹配环境事实。鉴权类仍需可执行约束判据，注入类待 RG-01～03。 |

近期附带修复：`pocs.result` 列 varchar(32) 装不下契约值 `not_exploitable_under_environment`（33 字符），迁移 `0024` 加宽至 64 并同步 models。

本地修复另调整 semantic-audit Finding 身份：约束文本经 NFKC、空白折叠和大小写归一后参与 ID，避免同一源码位置、同一 CWE 下不同安全约束互相冲突。

历史任务的”完成”只代表当时记录的局部产物和验证，不能覆盖上表未解决的问题。旧 `EXPLOITABLE` 记录未追认为新协议结论。

## 进行中 / 待验证

T46–T51（脱壳工具链 ADR-028、审计检查点 ADR-029、调查记忆 ADR-030、agent 引导投放 ADR-031、诊断证据化 ADR-032、动态验证链路 ADR-031 配套）均已完成并栈内验证。下表只保留未开始、待验证或受阻的事项，实现明细见 Git 提交。

| 事项 | 状态 | 已确认结果与剩余动作 |
|---|---|---|
| RealWorld 验收样本登记（FFmpeg CVE-2026-64830 / 7-Zip CVE-2026-48095） | 已登记 | `code/tests/fixtures/realworld/` 登记两个 2026 年披露样本：10 个官方工件 SHA-256 锁定（不入库，`download.sh` 幂等复现）、真值锚点经漏洞版↔修复版源码 diff 核对（FFmpeg 缺陷在 `libavformat/mpeg.c` vobsub 队列索引，8.1.3 修复；7-Zip 在 `NtfsHandler.cpp` ClusterSizeLog 校验，26.01 收紧 `>30`→`>21`）、R1/R2/R3 分轨验收标准。R1 源码审计轨、R2 二进制导入轨待栈内执行验证；R3 目标绑定动态轨依赖 P1 C/C++ BuildProfile。 |
| ADR-036 P0 目标绑定验证 | 已合并部署 | `main @ f5bc37e` 全量 Python 门禁通过；本轮在分支上追加 CR-04~08 修复后重建 9 个镜像并重启，API ready、Web 200、数据库迁移 0024、真实 Runner 正反例 3 passed。模型驱动的 candidate → target exception/behavior observation → **模型 re-review** → confirmed 全链仍需网关配置观察。 |
| T60 大文件/项目扫描审计优化 | 待验证 | 拉格朗 18MB PE 的 `import/semantic_audit/report` 栈内成功（函数 20,000/伪代码 20,000/指令 200,000；共修 7 层缺陷）。反向规划偶发 `binary_planning_degraded`，需查明原因；本轮已落地 CR-08 截断计数与 CR-07 邻域下推，待复跑同样本核对耗时与覆盖计数。 |
| T59 导入结果复用（缓存）+ 审计基线上下文 | 待验证 | 同输入重导入 20.4 分钟→**0.5 秒**，produced 版本一致；用正常样本补 `analysis_baseline` 真实模型回归。 |
| T58 大项目前端分页（函数工作台） | 待验证 | 已部署，载荷 27.9MB→178.6KB；待浏览器确认 snow shot 任务页内存/CPU 恢复。 |
| T56 任务活动反馈与轮询优化 | 待验证 | 已部署，迁移 0022 已应用、activity 端点线上实测；待真实长任务观察心跳档位、审计轮次与轮询节奏。 |
| T55 多语言源码审计（4→13 种语言） | 待验证 | 已部署，13 个语法包容器内验证通过；待多语言样本栈内 E2E：索引→静态线索→审计。 |
| T54 agent 上下文分层（ADR-035） | 待验证 | 代码已合并 main（`654b5bc`）；待栈内真实模型回归提示词变更（系统提示新增 journal 使用句）。 |
| T53 候选 Finding 自动 PoC 验证（ADR-034） | 目标异常语义已收窄 | 模型输出受限 `{driver: {target_callable, input_mode}, crafted_input, control_input, rationale}`；bundle 化执行。可重复目标异常记录为 `verified_trigger` observation，但 POC 结果为 `INCONCLUSIVE`、证据为 `SUPPORTING`，不能单独证明漏洞影响或触发确认。本轮新增 `verified_behavior` 差分判定：为鉴权类提供可确认证据链（见 CR-04 行），注入类仍差 `protection_analysis`。 |
| T52 模型供应商注册表（ADR-033） | 待验证 | 已部署，DeepSeek 仍走 legacy `model_tiers` 回退；待 Web 设置页重建供应商并绑定四个智能体，再用固定样本审计。 |
| 项目删除 500 修复（自引用表 `created_at` 并列删序） | 待验证 | 已合并 main，用户暂缓镜像重建；待部署并验证界面删除，`IntegrityError`→结构化 409 映射仍可改进。 |

口径校正：T60 的 20,000 函数 / 200,000 指令恰好等于当前聚合上限，此前不能据此推断该 PE 的事实已全部索引；本轮 CR-08 落地后，重跑同样本可直接从 result `coverage` 与 baseline `truncated_collections` 读出截断判定（待复跑核对）。T58 的前端分页不含审计/PAIR 后端查询——后者本轮已做入口探针与邻域下推优化（CR-07），工作区仍为单次全量装载。

运维参考：门禁标准环境是 dev 容器（`docker compose -f compose.yaml -f compose.dev.yaml up -d dev`，之后 exec 进容器跑 pytest/ruff/pyright 与栈内 E2E；PG/Redis opt-in 默认已指向栈内 `postgres:5432`/`redis:6379`，无需再传 `VULNWEAVER_TEST_*` 环境变量，其他环境用同名变量覆盖）。切分支/合并后使用 `uv sync --all-packages --no-editable --reinstall` 重建 workspace 包；省略 `--reinstall` 会复用旧 wheel，即使显示卸载/安装也可能静默运行旧代码（Q-003）。

## 已确认决策（摘要）

- 动态执行（Fuzz/Proof/Exploit）只经 Sandbox Runner；默认禁网、非 root、只读输入。
- 控制面/执行面分离；普通 Worker 不挂 Docker Socket。
- 原始工件不可变；派生工件带摘要、父工件与生成配置。
- ADR-021：先必跑审计基线，再 Finding 驱动复核与深审。
- ADR-025：`resource_budget` 惰性簿记；沙箱不设计算配额。
- ADR-027：审计循环不设规划轮次上限，墙钟 deadline 兜底。
- ADR-028（2026-09-28）：分层静态脱壳工具链；unipacker 的 Unicorn 模拟与 angr 同属翻译式处理，原生执行边界不变；重工具只进 binary-tools 镜像。
- ADR-033（2026-09-30）：模型接入重构为供应商注册表+每智能体绑定；输出上限归模型配置，任务不再有 token 配额；审计 deadline 默认 8h、可配至 7 天。保持应用内网关库形态，`ChatTransport` 保留将来换 SDK 的口子。
- ADR-035（2026-09-30）：agent 上下文三层分层（钉住头部/journal 压缩中间/原样尾部）；压缩用确定性单行摘要而非 LLM 摘要调用；journal 是不可信数据、随检查点持久化；网关窗口兜底钉死 system 消息。
- ADR-036（2026-10-03，已接受）：保留控制面，逐阶段引入原目标绑定、独立验证和隔离评测。目标绑定 bundle 与 finding 交叉核对、入口独立观测和隔离评测依序推进。当前修复加入每轮目标子进程和超时；观测中的 `target_exception_attributed` 表示可重复异常，尚不能据此把漏洞影响视为已证实。C/C++ 构建绑定、InvestigationCase、隔离评测仍在后续阶段。

## 经验教训（仍有效）

- **改 persistence（尤其迁移）后必须重建 dispatcher 镜像**：`migrate` 服务跑在 dispatcher 镜像里，只重建 api/worker 时迁移静默跳过新迁移、无任何报错（T56 首次部署踩坑）。2026-10-03 再次确认：手工把栈库迁到 0024 后，旧 dispatcher 镜像的 migrate 服务会因「找不到更高 revision」直接 exit 1。
- **改沙箱协议必须同步重建三个镜像**（proof-tool/工具镜像、sandbox-runner 内嵌 profiles、dispatcher/migrate），缺一即行为分叉——本轮 proof argv 从 `--script` 改 `--bundle` 后 runner 容器仍用旧 wheel 构造 argv，失败形态是入口 argparse 报缺参数（`proof.tool_error`），不是 `arguments_rejected`。重建 binary-tools 后必须重启 sandbox-runner 重解析本地摘要，否则 `runtime_failed`（T60）。
- **opt-in 真实 Runner 测试写共享 CAS 需要权限**：卷属主是 10001，dev 容器用户（1000）默认不可写；`docker exec <runner> chmod -R a+rwX /var/lib/vulnweaver/artifacts` 一次性放开（dev 栈联调用），并把 `SANDBOX_RUNNER_TOKEN` 一并传入测试环境。注意"一次性"不持久：runner 此后新建的子目录仍属 10001 且按 umask 收权限，dev 容器再次写深层路径会报 `ArtifactStoreIOError`——重跑前重新执行同一条 chmod 即可。
- **对 PUT /api/settings 联调必须先 GET 全量再回写全量**：T57 曾用最小 body 整行覆盖 product_settings，清掉 legacy 模型配置与 angr_enabled。
- Q-025（已修复）：runner 热重载/镜像重建后 worker 缓存旧 digest 导致 `image_identity_mismatch`，client 层遇该失败码向 runner 重取权威 digest 重试一次。另有同失败码待查项：`ReconfigurableRunner` 热重载后 registry 与 profiles 可分叉，重启 runner 即愈，根因待查。
- **提示词/字符串改写必须先过 ruff 再 build 镜像**：转义损坏曾直接造成 worker 崩溃循环，docker build 不做语法检查拦不住。
- AFL：`AFL_NOOPT` 变量**存在即禁用插桩**（与值无关）；容器宿主 core_pattern 检查用 `AFL_IGNORE_PROBLEMS=1` 跳过。
- Q-003：Windows 中文路径不用 editable 安装；改动 `packages/` 后容器内需 `uv sync --reinstall-package <pkg>`，合并前全量门禁使用 `uv sync --all-packages --no-editable --reinstall`。2026-10-03 不带 `--reinstall` 的全量同步复用了旧 wheel，造成 29 项伪回归；强制重建后 682 passed。
- Q-023：Windows 上新建脚本注意 CRLF（容器 shebang 会断）；入口脚本保持 LF。
- **应用栈重建时 web 容器可能不被替换**：web 镜像分层缓存命中产生相同 image ID 时 `docker compose up -d` 不会重建容器，而 nginx 在启动时解析 `api` 主机名并缓存——API 容器换 IP 后经代理访问一律 502。用 `docker compose up -d --force-recreate web` 刷新。
- **真实 Runner opt-in 测试的令牌**：栈 `.env` 配置了 `SANDBOX_RUNNER_TOKEN` 后，runner 对工具 spec 查询返回 401；测试需 `-e SANDBOX_RUNNER_URL=http://sandbox-runner:8080 -e SANDBOX_RUNNER_TOKEN=<.env 同值>`，共享 CAS 卷的 `chmod a+rwX` 一次性放开在卷上持久有效。
- pyright strict 下 dataclass `field(default_factory=list)` 会被推断成 `list[Unknown]`（本仓库 pyright 版本行为）；用 `default_factory=lambda: []` 携带类型。
- 2026-10-03：TypedDict/StrEnum 从 JSON 反序列化后是裸字符串，枚举成员 `is` 比较恒 False——跨信任边界的数据一律用 `==`/`str()` 归一后比较（本次曾使 verified_trigger 被误判 inconclusive）。

## 最近验证

| 日期 | 验证 | 结果 |
|---|---|---|
| 2026-10-04 | 分支（`1ca1d20`）RF-01～02 修复门禁与栈内部署 | 新并行入口 `pnpm run check` 完整输出：**761 passed / 7 skipped、覆盖率 81.10%、总耗时 192.1s**（pytest 157.2s），Ruff、Pyright 0 errors、contracts `--check`、TypeScript 18 tests、Web 生产构建通过。重建 7 个镜像并重启；migrate exit 0（0024）、`/health/ready` ready、Web 200；真实 Runner 验收 **6 passed**。新增回归：网关传输失败（DEPENDENCY/retryable）经 Worker 结算自动重试并从断点恢复（第 0 页不重发）；截止测试时钟改为第 0 页完成后触发，断言 `next_page=1` 断点与 attempt 2 只跑剩余页。 |
| 2026-10-04 | 分支（`69cfba2`）RP-01～03 修复门禁与栈内部署 | 新并行入口 `pnpm run check` 完整输出：**760 passed / 7 skipped、覆盖率 81.07%、总耗时 184.5s**（pytest 148.7s），Ruff、Pyright 0 errors、contracts `--check`、TypeScript 18 tests、Web 生产构建通过。重建 7 个镜像并重启；migrate exit 0（0024）、`/health/ready` ready、Web 200；真实 Runner 验收 **6 passed**（含注入 forgery 负例）。新增回归：Worker 结算级截止超时重试并断点恢复（attempt 2 全覆盖）、页大小变更丢弃断点全量重审且 coverage 完整为真、跨页重复候选双证据链接同一 Finding。 |
| 2026-10-04 | 分支（`add7676`）RG-01～03 修复门禁与栈内部署 | 新并行入口 `pnpm run check` 完整输出：**757 passed / 7 skipped、覆盖率 81.05%、总耗时 177.5s**（pytest 143.6s），Ruff、Pyright 0 errors、contracts `--check`、TypeScript 18 tests、Web 生产构建通过。重建 proof-tool/api/dispatcher/orchestrator/analysis-worker/sandbox-runner/web 镜像并重启；migrate exit 0（0024）、`/health/ready` ready、Web 200。真实 Runner 验收 **6 passed**：既有正反例 3 项 + 新增注入 forgery 负例（exit-20 伪装、常量 sink：伪造落地于 observation/marker 但 `derive_established_facts` 仅得 `minimal_reproduction`，Finding 保持候选）与 profiler 致盲负例（无 reach 声明）。共享 CAS 卷 runner 建新目录后曾报 `ArtifactStoreIOError`，`chmod -R a+rwX` 后恢复。 |
| 2026-10-04 | 本轮质量门禁与分支复审（Linux dev 容器） | 旧串行入口全量：753 passed / 4 skipped、覆盖率 81.80%，pytest 自身 145.97 秒；新并行入口首次全量 167.9 秒。补 `proof`/`reporting` 覆盖并排除生成声明后，`pnpm run check` **753 passed / 4 skipped、扩展后覆盖率 81.18%、总耗时 190.7 秒**，Ruff、Pyright 0 errors、contracts `--check`、TypeScript 18 tests、Web 生产构建通过；`node --check scripts/check.mjs` 与 `git diff --check` 通过。人为移除 `pnpm` 的 PATH 负例返回 exit 1 并逐项报错。4 skipped 为 3 个真实 Runner 配置项和 1 个 Docker runtime opt-in；本轮未跑 Runner/镜像重建、未部署。RG-01～03 为静态代码路径推导，待隔离环境负例验收。 |
| 2026-10-04 | 分支（`3902c4e`）RA-01~05 修复门禁与栈内部署 | `pnpm run check:python`：**753 passed / 4 skipped**（修复过程一轮 752+1 失败系旧鉴权派生测试未同步 RA-02 语义，已更新）；Ruff、Pyright 0 errors、contracts `--check`、web lint/typecheck/18 tests 通过。重建 proof-tool/api/dispatcher/orchestrator/analysis-worker/sandbox-runner/web 镜像并重启；migrate exit 0（0024）、`/health/ready` ready、Web 200；真实 Runner 定向验收 **3 passed**。新增回归：sink 触发/清洁目标 entrypoint 正反例、相同摘要 forged 观测拒绝、无 sink 触发不写 sink_reached、多 Finding 约束提取、损坏片段硬失败、续跑聚合计数。 |
| 2026-10-04 | 分支（`708a4f4`）CR-04 收尾门禁与栈内部署 | `pnpm run check:python`：**742 passed / 4 skipped**（上一轮曾出现 1 项 worker 并行偶发 error，隔离/目录级/全量复跑均通过确认为偶发）；Ruff、Pyright、contracts `--check`、web lint/typecheck/18 tests 通过。重建 proof-tool/api/dispatcher/orchestrator/analysis-worker/sandbox-runner/web 镜像并重启；migrate exit 0（0024）、宿主机 `/health/ready` 返回 ready、Web 200；真实 Runner 定向验收 **3 passed**。注入全链确认回归 `test_injection_with_protection_enumeration_confirms` 通过。 |
| 2026-10-04 | 分支 `feat/realworld-acceptance-samples`（`92bb0d7`）CR-04~08 修复门禁与栈内部署 | `pnpm run check:python`：**735 passed / 4 skipped**，覆盖率 **81.79%**；Ruff、Pyright、contracts `--check`、web lint/typecheck/18 tests、`vite build` 通过。4 项跳过为 3 个需 Runner 配置的测试和 1 个 Docker runtime opt-in；重启后的真实 Runner 定向验收 **3 passed**（`SANDBOX_RUNNER_URL`/`SANDBOX_RUNNER_TOKEN` 取自栈 `.env`）。重建 proof-tool/fuzz-tool/api/dispatcher/orchestrator/analysis-worker/sandbox-runner/web/binary-tools 镜像并重建应用栈容器；migrate exit 0（版本 0024）、PostgreSQL/Redis healthy、API `/health/ready` ready、Web 200（web 容器需 `--force-recreate` 刷新 nginx 上游缓存，见经验教训）。 |
| 2026-10-04 | main `f5bc37e` 修复门禁与本地部署 | `pnpm run check:python`：**711 passed / 4 skipped**，覆盖率 **81.69%**；Ruff、Pyright、contracts `--check` 通过。跳过项为 3 个需 Runner 环境的测试和 1 个 Docker runtime opt-in；重启后的真实 Runner 定向验收 **3 passed**。重建 proof-tool/fuzz-tool/api/dispatcher/orchestrator/analysis-worker/sandbox-runner/web/binary-tools 镜像并重建应用栈容器；migrate 成功（版本 0024）、PostgreSQL/Redis healthy、API `/health/ready` 返回 ready、Web 返回 200、analysis-worker/dispatcher/orchestrator 正常启动。 |
| 2026-10-03 | main `62315c5` 本地部署 | 重建 api/web/analysis-worker/dispatcher/orchestrator/binary-tools/sandbox-runner 镜像并 `docker compose up -d`；PostgreSQL 与 Redis healthy，迁移和 artifact-init 正常退出，API `/health/ready` 返回 `{"status":"ready"}`，Web `127.0.0.1:8080` 返回 200。未运行 pytest/真实 Runner。 |
| 2026-10-03 | ADR-036 P0 合并后静态复审（main `04d1281`） | 沿 bundle→entrypoint→worker→review 与手动 proof API 追踪，发现 CR-09–11。未运行新负例的真实 Runner 验收；既有 2 passed 不能排除这些构造。 |
| 2026-10-03 | ADR-036 P0 合并与部署（main `6f81486`） | 重建 analysis-worker/api/orchestrator/web 镜像并 `up -d` 重启栈：migrate 服务 exit 0（栈库 0024），API `/health/ready` ready、web 宿主 `127.0.0.1:8080` 200、analysis-worker 正常启动且已装载 bundle/verifier 新代码，sandbox-runner 注册 proof-tool 新摘要。重启后 opt-in 真实 Runner 验收复跑 **2 passed**。未做：真实模型驱动的 re-review 全链观察（需网关配置）。 |
| 2026-10-03 | ADR-036 P0 目标绑定验证（Linux dev 容器 + 真实 Runner） | 全量门禁：`pnpm run check:python` pytest **703 passed / 7 skipped**、覆盖率 **82%**，ruff/pyright 0 errors；contracts `--check`、web svelte-check/18 tests/`vite build` 通过。**真实 Runner 验收**（`tests/proof/test_target_bound_runner.py`，重建 proof-tool/sandbox-runner/dispatcher 镜像、栈库迁至 0024 后）：正例 verified_trigger + 3/3 重放 + STRONG 证据入库 + 原样本版本不变；空脚本/伪造 marker+自崩/错误目标负例全部 `not_exploitable_under_environment` 且零证据，2 passed。入口级正反例（含篡改/摘要不符/未声明成员/符号链接）9 passed；证据→policy 真实 DB 回归 6 passed（含旧 `EXPLOITABLE` 兼容读取）。 |
| 2026-10-03 | 合并前完整门禁（Linux dev 容器） | 强制重建所有 workspace 包后，`pnpm run check`：pytest **682 passed / 5 skipped**、覆盖率 **81.59%**，ruff/pyright 通过，前端 18 tests、svelte-check 0 errors；contracts `--check` 与 Web `vite build` 通过。5 项跳过含 4 项缺真实 Runner 配置的 HTTP proof 回放和 1 项 Docker runtime opt-in；真实目标验证、镜像 E2E 和 benchmark 仍未覆盖。 |
| 2026-10-03 | proof/审计安全检查点（Linux dev 容器） | `uv run --no-sync pytest -q tests/proof tests/orchestrator/test_semantic_audit.py tests/orchestrator/test_code_audit.py tests/orchestrator/test_agent_fuzz_steering.py`：52 passed / 4 skipped（HTTP Runner 环境变量未提供）；随后补派生工件重复登记回归：定向 6 passed。受影响文件 ruff 通过，`pnpm run check:pyright`：0 errors。尚未运行真实 Runner、全量 pytest、镜像验证和 benchmark。 |
| 2026-10-03 | 主链路只读 code review（Linux dev 容器） | 定向测试 21 passed + 11 passed；无害 JSON 包装执行复现“内部脚本未运行但外层成功”；`_safe_replay_facts` 最小调用复现 markers 被过滤。未运行真实 PoC/Exploit 沙箱全链、大样本性能基准或全量测试。详见 `code/docs/code-review-2026-10-03.md`。 |
| 2026-10-02 | T56–T60 栈内部署与门禁 | 拉格朗 18MB PE 全链 succeeded；同输入重导入 0.5 秒复用；分页载荷 178.6KB；超时可配置验证超旧 600s 上限仍正常推进。全量 `pytest -n 4` 随任务递增 649→**678 passed / 5 skipped**，ruff、pyright 0 errors、svelte-check、web tests、vite build、contracts `--check` 均通过。 |

更早的门禁记录（T45–T55，2026-09-11 至 2026-10-01）与 T46–T52 各轮 E2E 细节见 Git 提交与 `code/docs/progress/`。

## 前轮审计修复（2026-10-04，`bce0a24` → `3902c4e`；RA-01 由 RG-01～03 重开）

| 编号 | 优先级 / 状态 | 原始发现与修复 |
|---|---|---|
| RA-01 | P0 / 已关闭（确认链撤除，`add7676`） | 前轮移除了"单凭输出差分写 `sink_reached`"的直接路径，并增加 `sys.setprofile` C 调用画像和重放要求；RG-01～03 复审指出目标仍可伪装 exit 20/致盲 profiler，且 sink 触发未证明输入进入 sink。最终修复：注入确认事实派生整体撤除（marker 仅诊断），Runner 负例固定边界；可信观测待 P0.5/传播判据提案。 |
| RA-02 | P0 / 已修复（鉴权降级为候选） | 原发现：约束文本 SHA-256 回显不检验违反关系，普通输入差异即派生鉴权确认事实。修复：删除 `_derived_poc_facts` 鉴权分支——`constraint_analysis`/`behavior_difference`/`reachable_path` 不再从差分证据派生，鉴权 Finding 回到候选；`constraint_digest` marker 保留为诚实溯源。可执行约束判据方向（断言 DSL/不变量探针）记入 [`code/docs/oracle-proposal-2026-10-04.md`](code/docs/oracle-proposal-2026-10-04.md) §5，解封需另行走 ADR 提案。回归：`test_auth_markers_derive_no_confirmation_facts`、gate 拒绝测试。 |
| RA-03 | P1 / 已修复 | 原发现：`_constraint_from_report` 把 `None == None` 当地址匹配，同 CWE 报告错取第一条约束。修复：源条目仅按确切 path+line 匹配，二进制条目须两侧都有地址才比较；缺字段永不相等。回归：`test_constraint_extraction_requires_exact_location`、`..._ignores_partial_location_matches`、`..._matches_binary_address_on_both_sides`。 |
| RA-04 | P1 / 已修复 | 原发现：分页汇总读包装对象顶层 `findings`，分页 findings 全部丢失而 coverage 仍标 complete。修复：汇总读取 `fragment["report"]`，逐片段重验 CAS 摘要，缺失/不可读/摘要不符即 `semantic_audit.fallback_fragment_missing` 硬失败。回归：`test_resumed_aggregate_carries_every_page_finding`、`test_corrupted_page_fragment_fails_the_audit_instead_of_losing_findings`。 |
| RA-05 | P1 / 已修复 | 原发现：相同摘要 + `differed=true` 的合法 Schema 观测可通过行为验证。修复：`_behavior_matches_runs` 从运行摘要重算差分与 replay 一致性，报告布尔值仅作入口自检、不作为判据；相同摘要观测现被拒。回归：`test_identical_digests_with_differed_claim_is_rejected`。 |

审计原始证据（无害契约级复现）与首轮 18 passed 定向记录见 Git 历史（`78ce0f2`）。

## 下一步

**下一步：可信判据立项与真实项目闭环（RG-01～03、RP-01～03、RF-01～02 已关闭）**

1. **oracle P0.5（按 [`code/docs/oracle-proposal-2026-10-04.md`](code/docs/oracle-proposal-2026-10-04.md) 评审后立项）**：`VerificationRun.crash_kind` 契约扩展、entrypoint faulthandler/信号捕获、worker 观测事实映射与正反例——解释器信号经 OS wait status 传递，`os._exit` 无法伪造信号死亡，是当前架构内首个目标不可伪造的观测通道；完成后内存破坏类在含 C 扩展目标上具备 `repeatable_crash` 判据。注入确认事实的恢复依赖输入传播判据提案；鉴权类解封依赖 §5 的可执行约束判据。
2. **P1 最小真实项目闭环**：固定 1–3 个获授权开源解析器项目构建（BuildProfile、完整 TargetSnapshot、原目标链接验证），复用原 fuzz target；接入已知复现与源码盲发现 adapter。sanitizer 崩溃 oracle 随该轨一并设计。
3. **审查清单回归观察**：用真实模型走 candidate → observation → 独立 re-review → policy 全链（当前应止步于候选）；复跑拉格朗 18MB PE 核对 CR-08 覆盖计数与 CR-07 审计耗时变化。

**收尾与观察（非阻塞）**

5. 完成上表中 T52–T60 的剩余验证与观察项；合并本分支入 main 后按惯例重建镜像。
6. RealWorld 验收样本 R1/R2 轨在栈内执行验证。
7. 逆向耗时优化（用户已问询，未立项）：binary-facts 时间的主体是 Ghidra headless 对 18MB PE 的全量自动分析+反编译（一次性容器每轮重建 Ghidra program DB 无缓存）。候选方向：①事实首轮降配（`max_pseudocode_functions` 按输入大小分级或首轮跳过伪代码、agent 按需定向请求——target_addresses 管道已存在可复用）；②Ghidra program DB 作为派生工件回投沙箱复用（需 profile 支持额外只读输入，设计变更）；③入口脚本并行反编译。动前者需按 ADR 纪律评审。
8. 真实壳扩展：UPX-defaced 经 unipacker 已实测；ConfuserEx/.NET 样本走 de4dotEx 待真实样本；MPRESS 三路受阻（官方死链/网络/wine bug），有可达环境时补。
9. 性能后续候选项：`agent_runs.save_progress` 每轮全量重写 decisions JSONB 的写放大（可追加表化）；ProjectView 打开时 artifact detail N+1；`AuditWorkspace.load` 在超大索引下的内存驻留（现已被入口探针隔离为单次装载）。
10. 首跑注册的 API 账号 `vw-e2e`（密码在测试脚本常量中）仅用于联调，正式使用时建议改密或换账号。
