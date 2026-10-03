# DEVELOPMENT STATUS

> 轻量交接台账。稳定规则与安全红线见 `AGENTS.md`；已完成任务（T45–T52 等）的实现明细与 2026-10-01 前的门禁记录已裁撤，见 Git 历史、PR 与 `code/docs/progress/`。

更新时间：2026-10-03（Asia/Shanghai）

## 当前焦点

2026-10-03 用户已接受 [`ADR-036`](code/docs/adr/036-target-bound-verification-and-benchmark-evaluation.md)，本轮完成其 **P0 目标绑定验证闭环**：版本化 `ExecutionBundleManifest`/`VerificationObservation` 契约、ExecutionBundle（驱动/只读原目标/对照与攻击输入，摘要逐成员校验）、重写的 proof 入口（驱动子进程执行、目标帧归因、对照输入先行、重放、篡改检测）、worker 侧独立判定（`verified_trigger` 才产生 STRONG 证据与 `EXPLOITABLE`）与证据→policy 数据库链路。**真实 Runner 正反例验收已通过**（原目标正例可重放；空脚本、伪造 marker、驱动自崩、错误目标、篡改目标均不确认；原样本版本不变；旧 `EXPLOITABLE` 记录兼容读取且回归确认不能确认任何 Finding）。P0 剩余部署收尾见「下一步」；P1（真实 C/C++ 项目构建、InvestigationCase、CR-05–07）与 P2+ 未开始。

系统定位为**面向真实世界样本的长线漏洞挖掘智能体系统**。逐项审查缺陷代码证据见 [`code/docs/code-review-2026-10-03.md`](code/docs/code-review-2026-10-03.md)。agent 主导挖掘和长线调查仍是产品方向，但不能用 Job 成功或历史测试通过替代漏洞验证。

当前目标绑定验证的**能力边界**：可验证目标类为 Python 源码样本（驱动经 SourceFileLoader/exec 调用原文件、崩溃帧归因到原目标文件路径）；C/C++ 原项目的构建/链接绑定（BuildProfile、完整 TargetSnapshot）属 P1；鉴权类 `constraint_analysis` 与注入类 `source_to_sink_path` 仍无独立判据来源，这两类 Finding 依旧不能被自动证据确认（保持候选或人工复核）。

## 当前阻碍与审查缺陷（2026-10-03）

| 编号 | 状态 | 影响与解除条件 |
|---|---|---|
| CR-01、CR-02 / P0 | 已完成（P0 范围） | 执行输入与元数据分离为 bundle 成员并逐成员摘要校验；原目标以只读成员绑定（TargetBinding：artifact/version/digest）；`SandboxStatus` 成功不再产生任何漏洞结论，结论仅由可信入口的 `VerificationObservation` 决定。真实 Runner 正反例验收通过（`tests/proof/test_target_bound_runner.py`，opt-in）。C/C++ 目标构建绑定转 P1。 |
| CR-03 / P1 | 已完成 | 生成脚本与 ExecutionBundle 均为独立 DERIVED 工件（bundle 父版本指向原样本版本）。数据库回归确认原样本 `current_version_id` 不变。 |
| CR-04 / P1 | 进行中 | 类型化 `verification_observation` 证据 + 白名单放行（契约校验后才可用）+ 内存类事实集推导 + 真实 DB「证据→事实→policy→confirmed」回归已通过；旧 `EXPLOITABLE` PoC 兼容读取且证明力为零已回归。**剩余**：鉴权 `constraint_analysis` 与注入类独立判据来源（无 fixtures/受控观测），完成前这两类不可自动确认。 |
| CR-05、CR-06 / P1 | 进行中 | Finding 已保留源代码行/二进制地址锚点，同函数不同源码行回归通过；源码搜索按唯一文件计数并报告未扫描数；`finding-report` 要求相应代码已读。相同行同 CWE 的不同约束仍可能冲突；回退审计仍截到 256 函数，跨版本同路径读取证明仍需加强。 |
| CR-07 / P1 | 未开始 | 审计重复全量读取函数，邻域查询每次装载整图。性能损失尚未量化。解除条件：大样本 SQL/内存/耗时基准及按需查询优化。 |
| CR-08 / P2 | 未开始 | 二进制聚合达上限后静默截断。解除条件：显式记录输入数、保留数、截断原因和受影响范围，并验证覆盖信息进入报告。 |

本轮附带修复：`pocs.result` 列 varchar(32) 装不下契约值 `not_exploitable_under_environment`（33 字符，旧代码从不产生该值故未触发），迁移 `0024` 加宽至 64 并同步 models。

历史任务的“完成”只代表当时记录的局部产物和验证，不能覆盖上表未解决的问题。旧 `EXPLOITABLE` 记录未追认为新协议结论。

## 进行中 / 待验证

T46–T51（脱壳工具链 ADR-028、审计检查点 ADR-029、调查记忆 ADR-030、agent 引导投放 ADR-031、诊断证据化 ADR-032、动态验证链路 ADR-031 配套）均已完成并栈内验证。下表只保留未开始、待验证或受阻的事项，实现明细见 Git 提交。

| 事项 | 状态 | 已确认结果与剩余动作 |
|---|---|---|
| ADR-036 P0 目标绑定验证 | 待验证（部署收尾） | 代码、测试与真实 Runner 验收已完成（见「最近验证」）。**analysis-worker 容器镜像尚未重建**，栈内 worker 仍运行旧 proof 代码；合并部署时需按运维参考重建全部服务镜像并重跑 opt-in 验收。 |
| CR-05/06 剩余、CR-07、CR-08 | 未开始 | 同行同 CWE 指纹、256 函数截断、全图邻域、聚合截断计数。 |
| T60 大文件/项目扫描审计优化 | 待验证 | 拉格朗 18MB PE 的 `import/semantic_audit/report` 栈内成功（函数 20,000/伪代码 20,000/指令 200,000；共修 7 层缺陷）。反向规划偶发 `binary_planning_degraded`，需查明原因；聚合上限可能截断，见 CR-08。 |
| T59 导入结果复用（缓存）+ 审计基线上下文 | 待验证 | 同输入重导入 20.4 分钟→**0.5 秒**，produced 版本一致；用正常样本补 `analysis_baseline` 真实模型回归。 |
| T58 大项目前端分页（函数工作台） | 待验证 | 已部署，载荷 27.9MB→178.6KB；待浏览器确认 snow shot 任务页内存/CPU 恢复。 |
| T56 任务活动反馈与轮询优化 | 待验证 | 已部署，迁移 0022 已应用、activity 端点线上实测；待真实长任务观察心跳档位、审计轮次与轮询节奏。 |
| T55 多语言源码审计（4→13 种语言） | 待验证 | 已部署，13 个语法包容器内验证通过；待多语言样本栈内 E2E：索引→静态线索→审计。 |
| T54 agent 上下文分层（ADR-035） | 待验证 | 代码已合并 main（`654b5bc`）；待栈内真实模型回归提示词变更（系统提示新增 journal 使用句）。 |
| T53 候选 Finding 自动 PoC 验证（ADR-034） | 已完成（新协议） | poc_verification 走目标绑定驱动协议：模型输出 `{script, crafted_input, control_input, rationale}`，bundle 化执行并独立判定；`verified_trigger` → `EXPLOITABLE` + STRONG 证据（触发 re-review），否则 `INCONCLUSIVE`/`NOT_EXPLOITABLE_UNDER_ENVIRONMENT` 且无证据。真实 Runner 验收通过。 |
| T52 模型供应商注册表（ADR-033） | 待验证 | 已部署，DeepSeek 仍走 legacy `model_tiers` 回退；待 Web 设置页重建供应商并绑定四个智能体，再用固定样本审计。 |
| 项目删除 500 修复（自引用表 `created_at` 并列删序） | 待验证 | 已合并 main，用户暂缓镜像重建；待部署并验证界面删除，`IntegrityError`→结构化 409 映射仍可改进。 |

口径校正：T60 的 20,000 函数 / 200,000 指令恰好等于当前聚合上限，不能据此推断该 PE 的事实已全部索引（需 CR-08 的截断计数才能判定覆盖范围）；T58 的前端分页不含 CR-07 的审计/PAIR 后端全量查询。

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
- ADR-036（2026-10-03，已接受）：保留控制面，逐阶段引入原目标绑定、独立验证和隔离评测。**P0 已实现**：单 input_ref 承载版本化 ExecutionBundle（manifest/driver/只读 target/inputs/controls，逐成员摘要校验）；可信入口独立观测（目标帧归因、对照输入先行、2 次重放、篡改检测、自报主张仅记录不采信）；`verified_trigger` 才产生 STRONG `verification_observation` 证据与 `EXPLOITABLE`，`SandboxStatus` 成功与漏洞判定彻底分离；内存类事实集（repeatable_crash/matching_environment/controllable_input）经白名单+契约校验进入 policy。C/C++ 构建绑定、InvestigationCase、隔离评测仍在后续阶段。

## 经验教训（仍有效）

- **改 persistence（尤其迁移）后必须重建 dispatcher 镜像**：`migrate` 服务跑在 dispatcher 镜像里，只重建 api/worker 时迁移静默跳过新迁移、无任何报错（T56 首次部署踩坑）。2026-10-03 再次确认：手工把栈库迁到 0024 后，旧 dispatcher 镜像的 migrate 服务会因「找不到更高 revision」直接 exit 1。
- **改沙箱协议必须同步重建三个镜像**（proof-tool/工具镜像、sandbox-runner 内嵌 profiles、dispatcher/migrate），缺一即行为分叉——本轮 proof argv 从 `--script` 改 `--bundle` 后 runner 容器仍用旧 wheel 构造 argv，失败形态是入口 argparse 报缺参数（`proof.tool_error`），不是 `arguments_rejected`。重建 binary-tools 后必须重启 sandbox-runner 重解析本地摘要，否则 `runtime_failed`（T60）。
- **opt-in 真实 Runner 测试写共享 CAS 需要权限**：卷属主是 10001，dev 容器用户（1000）默认不可写；`docker exec <runner> chmod -R a+rwX /var/lib/vulnweaver/artifacts` 一次性放开（dev 栈联调用），并把 `SANDBOX_RUNNER_TOKEN` 一并传入测试环境。
- **对 PUT /api/settings 联调必须先 GET 全量再回写全量**：T57 曾用最小 body 整行覆盖 product_settings，清掉 legacy 模型配置与 angr_enabled。
- Q-025（已修复）：runner 热重载/镜像重建后 worker 缓存旧 digest 导致 `image_identity_mismatch`，client 层遇该失败码向 runner 重取权威 digest 重试一次。另有同失败码待查项：`ReconfigurableRunner` 热重载后 registry 与 profiles 可分叉，重启 runner 即愈，根因待查。
- **提示词/字符串改写必须先过 ruff 再 build 镜像**：转义损坏曾直接造成 worker 崩溃循环，docker build 不做语法检查拦不住。
- AFL：`AFL_NOOPT` 变量**存在即禁用插桩**（与值无关）；容器宿主 core_pattern 检查用 `AFL_IGNORE_PROBLEMS=1` 跳过。
- Q-003：Windows 中文路径不用 editable 安装；改动 `packages/` 后容器内需 `uv sync --reinstall-package <pkg>`，合并前全量门禁使用 `uv sync --all-packages --no-editable --reinstall`。2026-10-03 不带 `--reinstall` 的全量同步复用了旧 wheel，造成 29 项伪回归；强制重建后 682 passed。
- Q-023：Windows 上新建脚本注意 CRLF（容器 shebang 会断）；入口脚本保持 LF。
- 2026-10-03：TypedDict/StrEnum 从 JSON 反序列化后是裸字符串，枚举成员 `is` 比较恒 False——跨信任边界的数据一律用 `==`/`str()` 归一后比较（本次曾使 verified_trigger 被误判 inconclusive）。

## 最近验证

| 日期 | 验证 | 结果 |
|---|---|---|
| 2026-10-03 | ADR-036 P0 目标绑定验证（Linux dev 容器 + 真实 Runner） | 全量门禁：`pnpm run check:python` pytest **703 passed / 7 skipped**、覆盖率 **82%**，ruff/pyright 0 errors；contracts `--check`、web svelte-check/18 tests/`vite build` 通过。**真实 Runner 验收**（`tests/proof/test_target_bound_runner.py`，重建 proof-tool/sandbox-runner/dispatcher 镜像、栈库迁至 0024 后）：正例 verified_trigger + 3/3 重放 + STRONG 证据入库 + 原样本版本不变；空脚本/伪造 marker+自崩/错误目标负例全部 `not_exploitable_under_environment` 且零证据，2 passed。入口级正反例（含篡改/摘要不符/未声明成员/符号链接）9 passed；证据→policy 真实 DB 回归 6 passed（含旧 `EXPLOITABLE` 兼容读取）。 |
| 2026-10-03 | 合并前完整门禁（Linux dev 容器） | 强制重建所有 workspace 包后，`pnpm run check`：pytest **682 passed / 5 skipped**、覆盖率 **81.59%**，ruff/pyright 通过，前端 18 tests、svelte-check 0 errors；contracts `--check` 与 Web `vite build` 通过。5 项跳过含 4 项缺真实 Runner 配置的 HTTP proof 回放和 1 项 Docker runtime opt-in；真实目标验证、镜像 E2E 和 benchmark 仍未覆盖。 |
| 2026-10-03 | proof/审计安全检查点（Linux dev 容器） | `uv run --no-sync pytest -q tests/proof tests/orchestrator/test_semantic_audit.py tests/orchestrator/test_code_audit.py tests/orchestrator/test_agent_fuzz_steering.py`：52 passed / 4 skipped（HTTP Runner 环境变量未提供）；随后补派生工件重复登记回归：定向 6 passed。受影响文件 ruff 通过，`pnpm run check:pyright`：0 errors。尚未运行真实 Runner、全量 pytest、镜像验证和 benchmark。 |
| 2026-10-03 | 主链路只读 code review（Linux dev 容器） | 定向测试 21 passed + 11 passed；无害 JSON 包装执行复现“内部脚本未运行但外层成功”；`_safe_replay_facts` 最小调用复现 markers 被过滤。未运行真实 PoC/Exploit 沙箱全链、大样本性能基准或全量测试。详见 `code/docs/code-review-2026-10-03.md`。 |
| 2026-10-02 | T56–T60 栈内部署与门禁 | 拉格朗 18MB PE 全链 succeeded；同输入重导入 0.5 秒复用；分页载荷 178.6KB；超时可配置验证超旧 600s 上限仍正常推进。全量 `pytest -n 4` 随任务递增 649→**678 passed / 5 skipped**，ruff、pyright 0 errors、svelte-check、web tests、vite build、contracts `--check` 均通过。 |

更早的门禁记录（T45–T55，2026-09-11 至 2026-10-01）与 T46–T52 各轮 E2E 细节见 Git 提交与 `code/docs/progress/`。

## 下一步

**优先：P0 收尾与 P1 启动（ADR-036）**

1. **P0 部署收尾**：合并部署时重建 analysis-worker/api/orchestrator 镜像（worker 侧新 proof 逻辑入镜像），随后用固定教学样本在栈内跑一次真实 PoC 全链（candidate → poc_verification → verified_trigger → re-review → confirmed），并按需重放 opt-in 验收。
2. **P1 最小真实项目闭环**：固定 1–3 个获授权开源解析器项目构建（BuildProfile、完整 TargetSnapshot、原目标链接验证），复用原 fuzz target；接入已知复现与源码盲发现 adapter。同时补 CR-04 剩余：鉴权 `constraint_analysis` 与注入类独立判据来源（身份/权限夹具、受控 sink 观测），无判据类别保持候选。
3. **P1（CR-05–07）**：补相同行同 CWE 不同约束的稳定指纹、二进制双地址和跨版本同路径读取回归；消除单次回退审计 256 函数截断。再测量大样本 SQL、字节量、延迟和内存，优化重复加载与全图邻域查询。
4. **P2（CR-08）**：为二进制分析记录输入量、保留量、截断原因与影响范围，并验证覆盖信息进入报告。更广的 benchmark 扩展按 ADR-036 提案阶段推进；SEC-bench Pro 内核轨与现有沙箱红线不兼容，暂不支持。

**收尾与观察（非阻塞）**

5. 完成上表中 T52–T60 的剩余验证与观察项。
6. 逆向耗时优化（用户已问询，未立项）：binary-facts 时间的主体是 Ghidra headless 对 18MB PE 的全量自动分析+反编译（一次性容器每轮重建 Ghidra program DB 无缓存）。候选方向：①事实首轮降配（`max_pseudocode_functions` 按输入大小分级或首轮跳过伪代码、agent 按需定向请求——target_addresses 管道已存在可复用）；②Ghidra program DB 作为派生工件回投沙箱复用（需 profile 支持额外只读输入，设计变更）；③入口脚本并行反编译。动前者需按 ADR 纪律评审。
7. 真实壳扩展：UPX-defaced 经 unipacker 已实测；ConfuserEx/.NET 样本走 de4dotEx 待真实样本；MPRESS 三路受阻（官方死链/网络/wine bug），有可达环境时补。
8. 性能后续候选项：`pair.neighborhood` 全图入 Python 改递归 CTE 下推；agent_runs `save_progress` 每轮全量重写 decisions JSONB 的写放大（可追加表化）；ProjectView 打开时 artifact detail N+1。
9. 首跑注册的 API 账号 `vw-e2e`（密码在测试脚本常量中）仅用于联调，正式使用时建议改密或换账号。
