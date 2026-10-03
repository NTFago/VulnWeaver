# DEVELOPMENT STATUS

> 轻量交接台账。稳定规则与安全红线见 `AGENTS.md`；已完成任务（T45–T52 等）的实现明细与 2026-10-01 前的门禁记录已裁撤，见 Git 历史、PR 与 `code/docs/progress/`。

更新时间：2026-10-03（Asia/Shanghai）

## 当前焦点

2026-10-03 架构改进提案已形成：[`面向真实世界 benchmark 的架构改进`](code/docs/benchmark-oriented-architecture.md) 与 [`ADR-036（提议）`](code/docs/adr/036-target-bound-verification-and-benchmark-evaluation.md)。保留控制面，优先建立真实目标构建、可证伪调查、独立验证和隔离评测；设计文档已完成，P0–P4 实现均未开始。新增能力缺口：当前源码 harness 路径编译独立生成程序，未在该路径构建/链接原项目，不能将其崩溃作为原项目漏洞证据。

系统定位为**面向真实世界样本的长线漏洞挖掘智能体系统**。当前首要焦点是修复 2026-10-03 主链路代码审查发现的结果可信度、确认断链和漏报问题；逐项代码证据、风险与验收入口见 [`code/docs/code-review-2026-10-03.md`](code/docs/code-review-2026-10-03.md)。agent 主导挖掘和长线调查仍是产品方向，但不能用 Job 成功或历史测试通过替代漏洞验证。

历史记录显示部署栈曾重建运行，导入、语义审计、报告及 fuzz 的指定样本链路曾通过；本轮未重新检查服务在线状态，也未验证真实 PoC/Exploit 全链。自动 PoC/Exploit 的 `COMPLETED`/`EXPLOITABLE` 目前不能视为样本漏洞已复现。

## 当前阻碍与审查缺陷（2026-10-03）

| 编号 | 状态 | 影响与解除条件 |
|---|---|---|
| CR-01、CR-02 / P0 | 受阻 | 自动生成的 Python 脚本被存为 JSON，proof entrypoint 执行的是外层 JSON 表达式；沙箱请求又只提供脚本，没有目标样本。工具退出成功会被映射为 `EXPLOITABLE`。解除条件：修复脚本格式、目标输入协议与基于样本观测的成功判据，并完成真实 runner 正反例验收。当前暂停将自动验证状态解释为漏洞可利用结论。 |
| CR-03 / P1 | 未开始 | PoC 被登记为原样本的新版本并推进 `current_version_id`。解除条件：独立派生工件、原样本当前版本不变的数据库回归。 |
| CR-04 / P1 | 受阻 | PoC 证据写入 `markers`，复核事实白名单删除它；鉴权类 `constraint_analysis` 缺自动事实来源。解除条件：证据到政策门禁的真实数据库链路测试及事实映射修复。 |
| CR-05、CR-06 / P1 | 未开始 | 同函数同 CWE 候选发生 ID 冲突而丢弃；源码搜索按函数计文件数，回退审计截到 256 函数；`finding-report` 没有强制读代码。解除条件：锚点粒度、搜索覆盖与报告门禁的正反例回归。 |
| CR-07 / P1 | 未开始 | 审计重复全量读取函数，邻域查询每次装载整图。性能损失尚未量化。解除条件：大样本 SQL/内存/耗时基准及按需查询优化。 |
| CR-08 / P2 | 未开始 | 二进制聚合达上限后静默截断。解除条件：显式记录输入数、保留数、截断原因和受影响范围，并验证覆盖信息进入报告。 |

截至当前，上述审查与架构工作均为代码审查或文档提案，CR-01 至 CR-08 尚未修复。历史任务的“完成”只代表当时记录的局部产物和验证，不能覆盖上表未解决的问题。

## 进行中 / 待验证

T46–T51（脱壳工具链 ADR-028、审计检查点 ADR-029、调查记忆 ADR-030、agent 引导投放 ADR-031、诊断证据化 ADR-032、动态验证链路 ADR-031 配套）均已完成并栈内验证。下表只保留未开始、待验证或受阻的事项，实现明细见 Git 提交。

| 事项 | 状态 | 已确认结果与剩余动作 |
|---|---|---|
| CR-01 至 CR-08 修复 | 未开始 | 尚无代码修复；按「下一步」的 P0、P1、P2 顺序执行，验收入口见审查清单 |
| T60 大文件/项目扫描审计优化 | 待验证 | 拉格朗 18MB PE 的 `import/semantic_audit/report` 栈内成功（函数 20,000/伪代码 20,000/指令 200,000；共修 7 层缺陷）。反向规划偶发 `binary_planning_degraded`，需查明原因；聚合上限可能截断，见 CR-08。 |
| T59 导入结果复用（缓存）+ 审计基线上下文 | 待验证 | 同输入重导入 20.4 分钟→**0.5 秒**，produced 版本一致；用正常样本补 `analysis_baseline` 真实模型回归。 |
| T58 大项目前端分页（函数工作台） | 待验证 | 已部署，载荷 27.9MB→178.6KB；待浏览器确认 snow shot 任务页内存/CPU 恢复。 |
| T56 任务活动反馈与轮询优化 | 待验证 | 已部署，迁移 0022 已应用、activity 端点线上实测；待真实长任务观察心跳档位、审计轮次与轮询节奏。 |
| T55 多语言源码审计（4→13 种语言） | 待验证 | 已部署，13 个语法包容器内验证通过；待多语言样本栈内 E2E：索引→静态线索→审计。 |
| T54 agent 上下文分层（ADR-035） | 待验证 | 代码已合并 main（`654b5bc`）；待栈内真实模型回归提示词变更（系统提示新增 journal 使用句）。 |
| T53 候选 Finding 自动 PoC 验证（ADR-034） | 受阻 | 局部测试曾通过，但自动验证闭环被 CR-01/02/04 推翻；修复前不得用其结果评估挖掘能力。 |
| T52 模型供应商注册表（ADR-033） | 待验证 | 已部署，DeepSeek 仍走 legacy `model_tiers` 回退；待 Web 设置页重建供应商并绑定四个智能体，再用固定样本审计。 |
| 项目删除 500 修复（自引用表 `created_at` 并列删序） | 待验证 | 已合并 main，用户暂缓镜像重建；待部署并验证界面删除，`IntegrityError`→结构化 409 映射仍可改进。 |

口径校正：T60 的 20,000 函数 / 200,000 指令恰好等于当前聚合上限，不能据此推断该 PE 的事实已全部索引（需 CR-08 的截断计数才能判定覆盖范围）；T58 的前端分页不含 CR-07 的审计/PAIR 后端全量查询。

运维参考：门禁标准环境是 dev 容器（`docker compose -f compose.yaml -f compose.dev.yaml up -d dev`，之后 exec 进容器跑 pytest/ruff/pyright 与栈内 E2E；PG/Redis opt-in 默认已指向栈内 `postgres:5432`/`redis:6379`，无需再传 `VULNWEAVER_TEST_*` 环境变量，其他环境用同名变量覆盖）。切分支/合并后建议 `uv sync --all-packages --no-editable` 全量重装，避免未改包旧装（Q-003，该风险覆盖所有 workspace 包）。

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

## 经验教训（仍有效）

- **改 persistence（尤其迁移）后必须重建 dispatcher 镜像**：`migrate` 服务跑在 dispatcher 镜像里，只重建 api/worker 时迁移静默跳过新迁移、无任何报错（T56 首次部署踩坑）。
- **改沙箱 schema 必须同步重建三个镜像**（worker 请求/runner 校验/binary-tools argv），缺一即 `arguments_rejected`；重建 binary-tools 后必须重启 sandbox-runner 重解析本地摘要，否则 `runtime_failed`（T60）。
- **对 PUT /api/settings 联调必须先 GET 全量再回写全量**：T57 曾用最小 body 整行覆盖 product_settings，清掉 legacy 模型配置与 angr_enabled。
- Q-025（已修复）：runner 热重载/镜像重建后 worker 缓存旧 digest 导致 `image_identity_mismatch`，client 层遇该失败码向 runner 重取权威 digest 重试一次。另有同失败码待查项：`ReconfigurableRunner` 热重载后 registry 与 profiles 可分叉，重启 runner 即愈，根因待查。
- **提示词/字符串改写必须先过 ruff 再 build 镜像**：转义损坏曾直接造成 worker 崩溃循环，docker build 不做语法检查拦不住。
- AFL：`AFL_NOOPT` 变量**存在即禁用插桩**（与值无关）；容器宿主 core_pattern 检查用 `AFL_IGNORE_PROBLEMS=1` 跳过。
- Q-003：Windows 中文路径不用 editable 安装；改动 `packages/` 后容器内需 `uv sync --reinstall-package <pkg>`，否则**静默用旧代码**。
- Q-023：Windows 上新建脚本注意 CRLF（容器 shebang 会断）；入口脚本保持 LF。

## 最近验证

| 日期 | 验证 | 结果 |
|---|---|---|
| 2026-10-03 | 主链路只读 code review（Linux dev 容器） | 定向测试 21 passed + 11 passed；无害 JSON 包装执行复现“内部脚本未运行但外层成功”；`_safe_replay_facts` 最小调用复现 markers 被过滤。未运行真实 PoC/Exploit 沙箱全链、大样本性能基准或全量测试。详见 `code/docs/code-review-2026-10-03.md`。 |
| 2026-10-03 | 文档同步检查 | 盘点 71 个 Markdown 文档，按审查缺陷修改 19 个直接受影响文档；`git diff --check` 与相对链接检查通过。本轮无代码变更，未重跑全量代码门禁。 |
| 2026-10-03 | 状态台账与架构提案检查 | 修正缺陷优先级、标准化事项状态并合并重复的 P0 下一步；状态、架构方案、ADR-036 与索引的本地链接检查及 `git diff --check` 通过。仅文档变更，未运行代码测试或外部 benchmark。 |
| 2026-10-02 | T56–T60 栈内部署与门禁 | 拉格朗 18MB PE 全链 succeeded；同输入重导入 0.5 秒复用；分页载荷 178.6KB；超时可配置验证超旧 600s 上限仍正常推进。全量 `pytest -n 4` 随任务递增 649→**678 passed / 5 skipped**，ruff、pyright 0 errors、svelte-check、web tests、vite build、contracts `--check` 均通过。 |

更早的门禁记录（T45–T55，2026-09-11 至 2026-10-01）与 T46–T52 各轮 E2E 细节见 Git 提交与 `code/docs/progress/`。

## 下一步

**优先：恢复结论可信度（CR 修复）**

1. **P0（CR-01–04，未开始）**：ADR-036 仍为提议，尚未形成已接受的架构决策。推进前先明确是否接受其目标绑定和独立验证边界；首个开发任务是固定一个获授权解析器，定稿版本化 TargetSnapshot/ExecutionBundle/VerificationObservation 契约，并在 Linux 容器的真实 Runner 上建立原目标正例及空脚本、伪造成功标记、错误目标、harness 自身崩溃负例。随后修复 CR-01/02/03/04，跑通证据到 policy 的数据库链路。修复前不得用自动 PoC/Exploit 结果评估挖掘能力。
2. **P1（CR-05–07）**：修复 Finding 精确锚点、源码搜索/审计覆盖，再测量大样本 SQL、字节量、延迟和内存，优化重复加载与全图邻域查询。
3. **P2（CR-08）**：为二进制分析记录输入量、保留量、截断原因与影响范围，并验证覆盖信息进入报告。更广的 benchmark 扩展按 ADR-036 提案阶段推进；SEC-bench Pro 内核轨与现有沙箱红线不兼容，暂不支持。

**收尾与观察（非阻塞）**

4. 完成上表中 T52–T60 的剩余验证与观察项。
5. 逆向耗时优化（用户已问询，未立项）：binary-facts 时间的主体是 Ghidra headless 对 18MB PE 的全量自动分析+反编译（一次性容器每轮重建 Ghidra program DB 无缓存）。候选方向：①事实首轮降配（`max_pseudocode_functions` 按输入大小分级或首轮跳过伪代码、agent 按需定向请求——target_addresses 管道已存在可复用）；②Ghidra program DB 作为派生工件回投沙箱复用（需 profile 支持额外只读输入，设计变更）；③入口脚本并行反编译。动前者需按 ADR 纪律评审。
6. 真实壳扩展：UPX-defaced 经 unipacker 已实测；ConfuserEx/.NET 样本走 de4dotEx 待真实样本；MPRESS 三路受阻（官方死链/网络/wine bug），有可达环境时补。
7. 性能后续候选项：`pair.neighborhood` 全图入 Python 改递归 CTE 下推；agent_runs `save_progress` 每轮全量重写 decisions JSONB 的写放大（可追加表化）；ProjectView 打开时 artifact detail N+1。
8. 首跑注册的 API 账号 `vw-e2e`（密码在测试脚本常量中）仅用于联调，正式使用时建议改密或换账号。
