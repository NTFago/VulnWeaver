# DEVELOPMENT STATUS

> 轻量交接台账。稳定规则与安全红线见 `AGENTS.md`；历史课设阶段的任务明细见 Git 历史、PR 与 `code/docs/progress/`。

更新时间：2026-09-30（Asia/Shanghai）

## 当前焦点

系统定位为**面向真实世界样本的长线漏洞挖掘智能体系统**。当前主线（用户新 goal）：**agent 主导挖掘、降低对工具结果的依赖、长线作战**——T48 项目级调查记忆已落地（ADR-030）。

部署栈已在本分支上**全部重建并运行**（postgres/redis/api/orchestrator/dispatcher/analysis-worker/sandbox-runner/web/binary-tools 全部 Up），模型经 Web 设置接入，栈内端到端已通过（见验证记录）。

## 进行中

| 事项 | 负责人 / 分支 | 状态 |
|---|---|---|
| T53 候选 Finding 自动 PoC 复现验证（ADR-034） | ZCode / `feat/candidate-poc-verification` | **完成（代码+测试，未栈内 E2E）**：CANDIDATE Finding 在审计/复核结算后自动投放一次 PoC 复现 PROOF Job（`PocVerificationScheduler`，幂等键 `poc_verification:<finding_id>`；门禁=项目 `exploit_validation_enabled` + proof 镜像 pin + 脚本安全校验）；脚本生成 baseline `poc_verification`（提示词要求最小复现 + 末行 `POC_MARKERS:` 结构化标记）；executor 从沙箱 stdout 解析标记，COMPLETED 运行落 `POC_VERIFICATION_RESULT` STRONG 证据并携带 `evidence_ids`（激活既有 PROOF 证据→定向 re-review 路径）；`derive_established_facts` 新增注入类（`source_to_sink_path`/`protection_analysis`）与认证类（`behavior_difference`/`reachable_path`）推导——确认仍只走独立 re-review + `evaluate_confirmation`，"模型自我确认"红线不变。契约新增证据类型 + 迁移 0021 放开 `evidence.type` CHECK。dev 容器全量 `pytest -n 4` **616 passed / 5 skipped**、ruff、pyright 0 errors。**待验证**：栈内真实模型端到端（投放到沙箱真跑） |
| **缺陷（已修复，待部署）**：项目删除 500——`DeletionRepository` 按单一 `created_at DESC` 删除自引用表，时间戳并列时顺序不定 | ZCode / 已合并 main `78842fd`（origin/fix/project-delete-fk-tie，本地分支与 worktree 已清理） | **根因（2026-09-30，线上复现）**：`repositories.py` `delete_project`/`_delete_task_rows` 删除 `artifact_versions`（自引用 FK `parent_version_id`）、`reviews`（`supersedes_review_id`）、`annotations`（`supersedes_annotation_id`）时按 `created_at DESC` 单遍删除，假设"子版本时间戳更晚"；但工件管道在同一事务内为父子版本传入同一 `now()`，线上已有 **31 对 `created_at` 相同的父子版本**（15/18 个 e2e 残留项目受影响）。并列时 Postgres 返回顺序不定，父行先删即触发 RESTRICT FK → `sqlalchemy.exc.IntegrityError` 未映射到任何 API 错误 → 落入 catch-all → 500 "an unexpected internal error occurred"，事务回滚，重试恒失败。**修复**（`fix/persistence` 叶子优先迭代删除，三处自引用链统一走 `_delete_chain_leaves`，环链抛结构化不变量错误）：新增回归测试 `tests/persistence/test_deletion_repository.py` 3 例（修复前红/修复后绿）；定向 77 passed、ruff、pyright 0 errors；**用修复代码对线上 18 个残留项目回滚式试删 18/18 全通过**（事务内 93 个版本清空后 ROLLBACK，现场未动）。**待办**：用户暂缓镜像重建——部署后界面删除即恢复；`IntegrityError`→结构化 409 的错误映射仍可改进。注意 `alembic/versions/0011_finding_candidates.py`、`0012_review_history.py` 的建表语句与线上库不符（库中无这三张表但版本号已到 0020，属迁移文件事后改写），后续迁移变更勿把这组表当作删除遗漏项 |
| T52 模型接入重构：供应商注册表（ADR-033） | ZCode / `feat/model-provider-registry` | **完成（待合并）**：网关新增供应商注册表（`model_providers`+`agent_model_bindings`+`provider_api_keys`，每智能体绑定供应商模型并可配备用）、第三种线格式 OpenAI Responses、每模型上下文/最大输出元数据；任务级限制放开（审计 deadline 默认 8h、逆向规划 2h、上限 7 天；`resource_budget.max_model_tokens` 不再透传为输出上限，harness 8192 硬编码删除；单请求超时上限 600→3600s）；API 设置新增供应商校验/密钥合并/模型探测端点；Web 设置页重做为供应商卡片+绑定；旧 `model_tiers`/`review_model_*` 配置保留回退。已重建 api/orchestrator/analysis-worker/web 镜像并重启栈，worker 正常起循环 |
| T46 分层脱壳工具链 | ZCode / `feat/unpacking-toolchain` | **全部完成**（同前）+ 真实壳回归：MPRESS 官方站死链/archive.org 网络不可达/wine mmap bug 三路皆阻，改用**真实 UPX 壳（指纹抹除，`upx -d` 拒识）经 unipacker 模拟脱壳**的栈内 E2E 全绿（`methods=['unipacker']`，`scripts/e2e_unipacker_chain.py`） |
| T50 扫描器诊断证据化（ADR-032） | ZCode / 本分支 | **完成**：diagnostics 只落 TOOL_OUTPUT 证据（selector 补 severity/message），不再直接成为 CANDIDATE Finding；static-leads 改从证据层读线索；成为 Finding 的唯一路径是 agent 亲读代码后重新报告锚定 |
| T51 动态验证链路端到端打通 | ZCode / 本分支 | **完成**：afl-casr 镜像构建并注册；修复 4 个链路断点（harness-compile schema 条件必填 / entrypoint fuzz 参数必填与 bundle 白名单 / `AFL_NOOPT=0` 静默禁用插桩 / execs 竞态超预算）；`e2e_dynamic_verification.py` 全链全绿：审计→评审→fuzz 投放→harness 生成→AFL 真实执行→结果契约通过 |
| T49 agent 引导的动态验证投放（ADR-031） | ZCode / 本分支 | **完成**：审计结算时 agent 显式 `verification_request=fuzz` 的候选立即投放 fuzz 战役（早于 review；opt-in 门禁 + 每审计上限 4 + 调度器幂等去重全保留）；提示词同步为"请求即发起有界战役" |
| T48 项目级调查记忆（ADR-030） | ZCode / 已合并 `f6d354a` | **完成**：每次审计把自身结论（已锚定 Finding/锚定失败位置/覆盖状态）写为项目记忆工件，后续同项目审计装载进模型上下文；提示词新增记忆段；栈内 E2E 双任务验证每任务一版记忆 |
| T47 审计检查点与断点续跑（ADR-029） | ZCode / 同分支 | **完成**：`AgentLoop.progress` 回调 + `orchestration_checkpoints` 按落盘检查点；重试 attempt 续跑调查（决策/步骤/已报 Finding 不丢不重执行）；completed 检查点永不重放；配套长线校准（审计 deadline 1800→7200s、命令超时 180→600s）与提示词重写（修复损坏句+续跑语境+证据标准） |

T46 已完成边界（全部位于 `code/`，ADR-028 记录决策）：

- `packages/binary-analysis/src/vulnweaver_binary_analysis/unpacking.py`：`UnpackerChain` 多轮策略链（候选须通过严格解析验收，锚定原始摘要防回吐；多层壳逐层剥离，上限 4 轮）+ 四个解壳器 + `LiefRebuilder`（dump 后 PE 头再序列化修复）+ `BinaryUnpackSandboxAdapter`（worker 侧驱动容器内全链）。
- `executor.py`：本地链（UPX + XOR 恢复）失败且样本仍加壳时，经沙箱 `binary-unpack` 兜底；派生工件按方法登记（`upx-unpacked-binary` 保持不变，新增 `dotnet-cleaned-assembly` / `emulated-unpacked-binary` / `xor-recovered-binary`）。
- `profiles.py` + `apps/binary-tools/vulnweaver-binary-entrypoint` + sandbox-runner 服务：新增 `binary-unpack` ToolSpec/命令 profile（与 `binary-facts` 共用 binary-tools 镜像），入口脚本支持 `--mode unpack`。
- `headers.py`：PE 解析 CLR 数据目录（index 14），`BinaryMetadata.dotnet` 分发 de4dot。
- 镜像：binary-tools 增加 mono-complete + de4dotEx 3.10.0（net48，官方 release）+ `--extra unpack`（unipacker 1.0.8、lief 0.17.6）。

剩余：真实镜像端到端（见「下一步」）。

## 已确认决策（摘要）

- 动态执行（Fuzz/Proof/Exploit）只经 Sandbox Runner；默认禁网、非 root、只读输入。
- 控制面/执行面分离；普通 Worker 不挂 Docker Socket。
- 原始工件不可变；派生工件带摘要、父工件与生成配置。
- ADR-021：先必跑审计基线，再 Finding 驱动复核与深审。
- ADR-025：`resource_budget` 惰性簿记；沙箱不设计算配额。
- ADR-027：审计循环不设规划轮次上限，墙钟 deadline 兜底。
- **ADR-028（2026-09-28）**：分层静态脱壳工具链；unipacker 的 Unicorn 模拟与 angr 同属翻译式处理，原生执行边界不变；重工具只进 binary-tools 镜像。
- **ADR-033（2026-09-30）**：模型接入重构为供应商注册表+每智能体绑定（参考 cc-switch/dsh 的供应商形态）；输出上限归模型配置，任务不再有 token 配额；审计 deadline 默认 8h、可配至 7 天。保持应用内网关库形态（不引入独立网关服务），`ChatTransport` 保留将来换 SDK 实现的口子。

## 经验教训（仍有效）

- Q-025（已修复，2026-09-29）：runner 热重载/镜像重建后 worker 缓存的旧 digest 导致 `image_identity_mismatch`。修复在 client 层：`SandboxRunnerClient.run` 遇该失败码时向 runner 重取权威 digest 重试一次（`tests/proof/test_runner_client.py` 带状态假 runner 覆盖）。另：`vulnweaver-afl-casr:fixed` 镜像已构建并注册（compose 新增 `fuzz-tool` 构建服务），fuzz 投放链路的结构性断点已消除；`angr_enabled` 已开启。
- **提示词/字符串改写必须先过 ruff 再 build 镜像**：本轮一次转义损坏直接造成 worker 崩溃循环（SyntaxError），docker build 不做语法检查拦不住；修复后已恢复"改 packages 先 ruff/ast 后 build"纪律。
- Q-025（新，待查）：`ReconfigurableRunner` 设置热重载后 registry 与 profiles 可分叉（`sandbox.image_identity_mismatch`，重启 runner 即愈）；根因待查，怀疑 refresh 时 docker CLI 解析瞬时失败。
- Q-003：Windows 中文路径不用 editable 安装；改动 `packages/` 后容器内需 `uv sync --reinstall-package <pkg>`，否则**静默用旧代码**。
- Q-023：Windows 上新建脚本注意 CRLF（容器 shebang 会断）；本轮已将入口脚本规范化为 LF。

## 最近验证

| 日期 | 验证 | 结果 |
|---|---|---|
| 2026-09-30 | T53 候选 PoC 自动验证（dev 容器，栈内 PG） | 全量 `pytest -n 4`：**616 passed / 5 skipped**（新增调度器幂等/门禁 2、executor 标记解析/证据化/策略拒绝 3、钩子投放 1、事实推导 5 用例）；ruff 通过；pyright **0 errors**；迁移 0021 在临时库验证建库通过（alembic `op.drop_constraint` 会按命名约定二次包装约束名，改用原生 SQL，见迁移内注释） |
| 2026-09-30 | T52 模型接入重构（dev 容器，栈内 PG+Redis） | 全量 `pytest -n 4`：**605 passed / 5 skipped**（skip 仅 Docker 运行时 opt-in）；新增网关注册表 10 用例、Responses 线格式 3 用例、API 供应商设置/密钥合并/绑定校验用例、设置-网关边界用例；pyright **0 errors**；ruff 通过；svelte-check 0 errors、web 13 tests 过、vite build 过；api/orchestrator/analysis-worker/web 镜像重建并重启，worker 正常起循环并完成工具注册探测 |
| 2026-09-29 | T51 动态验证链路 E2E | opt-in 项目投递教学样本 fuzz-overflow.c：semantic_audit/review/fuzz 全部 succeeded，AFL++ 沙箱真实执行（-E 10000/-V 60），结果通过 FuzzToolSummary/CrashManifest 契约；fuzz 失败诊断能力补齐（sandbox stdout/stderr 尾部进 failure.details，triage reason 进消息） |
| 2026-09-29 | AFL 教训 | `AFL_NOOPT` 变量**存在即禁用插桩**（与值无关）——compile_env 里 `AFL_NOOPT=0` 使所有 harness 编译静默失去插桩，afl-fuzz 报 No instrumentation detected；`AFL_IGNORE_PROBLEMS=1` 才能跳过容器宿主 core_pattern 管道中止（`AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES` 只是不警告） |
| 2026-09-28 | T50 诊断证据化（dev 容器，栈内 PG） | orchestrator+binary_analysis+source_analysis **206 passed**；ruff 通过；pyright 0 errors；lineage 测试验证诊断零 Finding 行、线索从证据浮现 |
| 2026-09-28 | T49 智能体引导投放（dev 容器，栈内 PG） | 新增 2 用例（仅显式请求且锚定成功者被投放/未开启 opt-in 零投放）；orchestrator+binary_analysis **154 passed**；ruff 通过；pyright 0 errors |
| 2026-09-28 | T48 调查记忆（dev container 内执行，栈内 PG） | orchestrator+binary_analysis **152 passed**（新增 4 记忆用例）；ruff 通过；pyright 0 errors；栈内 E2E `e2e_investigation_memory.py`：同项目两任务全 succeeded，记忆工件 2 版 |
| 2026-09-28 | T47 + 真实壳回归 | `tests/orchestrator`+`tests/binary_analysis` **90 passed**（新增 5 续跑用例，其中 2 个在栈内 PostgreSQL 实跑）；ruff 通过；**pyright 0 errors**；栈内 E2E 双绿：真实 UPX 壳经 unipacker（`emulated-unpacked-binary`、分析切到脱壳镜像）与 XOR 壳回归（新提示词/新 deadline 下 `semantic_audit` 真实模型审计 succeeded） || 2026-09-28 | T46 部署栈内全链 E2E（`code/scripts/e2e_unpack_chain.py`，连续三跑全绿） | 上传自制 XOR 壳 ELF → `import`/`semantic_audit`/`report` 三 Job 全部 succeeded；`xor-recovered-binary` 派生摘要与内层 ELF 逐字节一致；**analysis 的 parent 即脱壳镜像**；模型（deepseek-flash）驱动的语义审计与报告真实产出 |
| 2026-09-28 | 部署栈重建 | 6 个服务镜像 + binary-tools 重建成功；期间修复**全新卷权限缺陷**：root 运行的一次性 migrate 服务初始化 CAS store 时把 `objects/sha256` 建成 root 所有，api(10001) 上传必 EACCES——artifact-init 现已预建该目录（compose.yaml），旧卷 chown 修复 |
| 2026-09-28 | T46 定向测试（Linux 容器 python:3.12-slim + uv 0.10，`uv sync --all-packages --no-editable --group dev`） | `tests/binary_analysis` **54 passed / 3 skipped**（跳过项为 PostgreSQL opt-in，与基线一致）；`tests/sandbox_runner` + `tests/contracts` + `tests/tool_runtime` **44 passed / 1 skipped**（Docker runtime opt-in）；`ruff check .` 通过；`uv lock` 纳入 lief 0.17.6 / unipacker 1.0.8 / unicorn-unipacker 1.0.3b7 |
| 2026-09-28 | pyright（node:24-slim 容器，pyright 1.1.413） | **0 errors**（lief 无存根问题以 `importlib.import_module` 隔离；跨模块私有名已提升为公开助手名） |
| 2026-09-28 | T46 全量测试 | `pytest -n 4`：401 passed / 2 failed（reporting 的 weasyprint 用例，装上 pango 后复跑 **10 passed**，纯环境缺失）/ 173 skipped（PG/Docker opt-in，本机临时容器无对应服务；定向四套件 98 passed） |
| 2026-09-28 | T46 镜像与容器内端到端 | `vulnweaver-binary-tools:fixed` 构建成功（mono-complete + de4dotEx 3.10.0 net48 + `--extra unpack`）；容器内 `--mode unpack` 对自制 XOR 壳 ELF 实测：UPX 探测→not_upx_packed 降级→**xor-recovery 命中**，`unpacked.bin` 与内层 ELF sha256 逐字节一致（`316f0550…`），报告含完整 methods/tool_runs/digests |
| 2026-09-11 | T45/T45-A~F 全量门禁 | `pytest` 556 passed / 5 skipped；ruff、pyright 0 错误；部署栈 UPX 加壳样本端到端通过（历史基线，栈现已清空） |

## 下一步

1. **T52 收尾（接手入口）**：当前部署的 DeepSeek 仍走 legacy `model_tiers` 回退（功能不变）；在 Web 设置页用"从预设创建→DeepSeek 官方"重建供应商（填 Key、绑定四个智能体）即完成迁移；迁移后用固定样本跑一次真实审计 E2E 验证注册表路径（`scripts/e2e_investigation_memory.py` 可复用）。OpenAI Responses 线格式只有单测覆盖，未对真实 Responses 端点联调。
2. **真实壳扩展**：UPX-defaced 经 unipacker 已实测；ConfuserEx/.NET 样本走 de4dotEx 待真实样本；MPRESS 三路受阻（官方死链/网络/wine bug），有可达环境时补。
3. **dev container 已启用为门禁标准环境**：`docker compose -f compose.yaml -f compose.dev.yaml up -d dev`，之后 `... exec dev bash -lc "cd /workspace/vulnweaver/code && ..."` 跑 pytest/ruff/pyright 与栈内 E2E（control-plane 直达 api/postgres）；注意 `.venv` 属主须为 dev 用户(1000)。测试的 PG/Redis opt-in 默认值已指向栈内服务名（`postgres:5432`/`redis:6379`，2026-09-30），容器内跑 pytest 无需再传 `VULNWEAVER_TEST_*` 环境变量；其他环境用同名变量覆盖，连不上时相关用例优雅 skip。
4. **长线下一块**：五块拼图+动态验证闭环已全部就位；候选方向：报告与工作台展示"线索→agent 结论"差异呈现、fuzz 崩溃证据经 ADR-027 §4 修订复核的运行时观察。
5. 分支清理已完成（2026-09-28）：`feat/unpacking-toolchain` 合并入 main 并推送；远程删除 13 个已合并/陈旧分支，保留未合并的 `demo/enrich-fixtures`、`feat/demo-final`（来历为演示用途，未动）。
6. 首跑注册的 API 账号 `vw-e2e`（密码在测试脚本常量中）仅用于联调，正式使用时建议改密或换账号。
