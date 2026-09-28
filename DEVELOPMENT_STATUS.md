# DEVELOPMENT STATUS

> 轻量交接台账。稳定规则与安全红线见 `AGENTS.md`；历史课设阶段的任务明细见 Git 历史、PR 与 `code/docs/progress/`。

更新时间：2026-09-28（Asia/Shanghai，第二轮更新）

## 当前焦点

系统定位为**面向真实世界样本的长线漏洞挖掘智能体系统**。当前主线（用户新 goal）：**agent 主导挖掘、降低对工具结果的依赖、长线作战**——T48 项目级调查记忆已落地（ADR-030）。

部署栈已在本分支上**全部重建并运行**（postgres/redis/api/orchestrator/dispatcher/analysis-worker/sandbox-runner/web/binary-tools 全部 Up），模型经 Web 设置接入（DeepSeek），栈内端到端已通过（见验证记录）。

## 进行中

| 事项 | 负责人 / 分支 | 状态 |
|---|---|---|
| T46 分层脱壳工具链 | ZCode / `feat/unpacking-toolchain` | **全部完成**（同前）+ 真实壳回归：MPRESS 官方站死链/archive.org 网络不可达/wine mmap bug 三路皆阻，改用**真实 UPX 壳（指纹抹除，`upx -d` 拒识）经 unipacker 模拟脱壳**的栈内 E2E 全绿（`methods=['unipacker']`，`scripts/e2e_unipacker_chain.py`） |
| T48 项目级调查记忆（ADR-030） | ZCode / `feat/agent-investigation-memory` | **完成**：每次审计把自身结论（已锚定 Finding/锚定失败位置/覆盖状态）写为项目记忆工件，后续同项目审计装载进模型上下文；提示词新增记忆段；栈内 E2E 双任务验证每任务一版记忆 |
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

## 经验教训（仍有效）

- **提示词/字符串改写必须先过 ruff 再 build 镜像**：本轮一次转义损坏直接造成 worker 崩溃循环（SyntaxError），docker build 不做语法检查拦不住；修复后已恢复"改 packages 先 ruff/ast 后 build"纪律。
- Q-025（新，待查）：`ReconfigurableRunner` 设置热重载后 registry 与 profiles 可分叉（`sandbox.image_identity_mismatch`，重启 runner 即愈）；根因待查，怀疑 refresh 时 docker CLI 解析瞬时失败。
- Q-003：Windows 中文路径不用 editable 安装；改动 `packages/` 后容器内需 `uv sync --reinstall-package <pkg>`，否则**静默用旧代码**。
- Q-023：Windows 上新建脚本注意 CRLF（容器 shebang 会断）；本轮已将入口脚本规范化为 LF。

## 最近验证

| 日期 | 验证 | 结果 |
|---|---|---|
| 2026-09-28 | T48 调查记忆（dev container 内执行，栈内 PG） | orchestrator+binary_analysis **152 passed**（新增 4 记忆用例）；ruff 通过；pyright 0 errors；栈内 E2E `e2e_investigation_memory.py`：同项目两任务全 succeeded，记忆工件 2 版 |
| 2026-09-28 | T47 + 真实壳回归 | `tests/orchestrator`+`tests/binary_analysis` **90 passed**（新增 5 续跑用例，其中 2 个在栈内 PostgreSQL 实跑）；ruff 通过；**pyright 0 errors**；栈内 E2E 双绿：真实 UPX 壳经 unipacker（`emulated-unpacked-binary`、分析切到脱壳镜像）与 XOR 壳回归（新提示词/新 deadline 下 `semantic_audit` 真实模型审计 succeeded） || 2026-09-28 | T46 部署栈内全链 E2E（`code/scripts/e2e_unpack_chain.py`，连续三跑全绿） | 上传自制 XOR 壳 ELF → `import`/`semantic_audit`/`report` 三 Job 全部 succeeded；`xor-recovered-binary` 派生摘要与内层 ELF 逐字节一致；**analysis 的 parent 即脱壳镜像**；模型（deepseek-flash）驱动的语义审计与报告真实产出 |
| 2026-09-28 | 部署栈重建 | 6 个服务镜像 + binary-tools 重建成功；期间修复**全新卷权限缺陷**：root 运行的一次性 migrate 服务初始化 CAS store 时把 `objects/sha256` 建成 root 所有，api(10001) 上传必 EACCES——artifact-init 现已预建该目录（compose.yaml），旧卷 chown 修复 |
| 2026-09-28 | T46 定向测试（Linux 容器 python:3.12-slim + uv 0.10，`uv sync --all-packages --no-editable --group dev`） | `tests/binary_analysis` **54 passed / 3 skipped**（跳过项为 PostgreSQL opt-in，与基线一致）；`tests/sandbox_runner` + `tests/contracts` + `tests/tool_runtime` **44 passed / 1 skipped**（Docker runtime opt-in）；`ruff check .` 通过；`uv lock` 纳入 lief 0.17.6 / unipacker 1.0.8 / unicorn-unipacker 1.0.3b7 |
| 2026-09-28 | pyright（node:24-slim 容器，pyright 1.1.413） | **0 errors**（lief 无存根问题以 `importlib.import_module` 隔离；跨模块私有名已提升为公开助手名） |
| 2026-09-28 | T46 全量测试 | `pytest -n 4`：401 passed / 2 failed（reporting 的 weasyprint 用例，装上 pango 后复跑 **10 passed**，纯环境缺失）/ 173 skipped（PG/Docker opt-in，本机临时容器无对应服务；定向四套件 98 passed） |
| 2026-09-28 | T46 镜像与容器内端到端 | `vulnweaver-binary-tools:fixed` 构建成功（mono-complete + de4dotEx 3.10.0 net48 + `--extra unpack`）；容器内 `--mode unpack` 对自制 XOR 壳 ELF 实测：UPX 探测→not_upx_packed 降级→**xor-recovery 命中**，`unpacked.bin` 与内层 ELF sha256 逐字节一致（`316f0550…`），报告含完整 methods/tool_runs/digests |
| 2026-09-11 | T45/T45-A~F 全量门禁 | `pytest` 556 passed / 5 skipped；ruff、pyright 0 错误；部署栈 UPX 加壳样本端到端通过（历史基线，栈现已清空） |

## 下一步

2. **真实壳扩展**：UPX-defaced 经 unipacker 已实测；ConfuserEx/.NET 样本走 de4dotEx 待真实样本；MPRESS 三路受阻（官方死链/网络/wine bug），有可达环境时补。
3. **dev container 已启用为门禁标准环境**：`docker compose -f compose.yaml -f compose.dev.yaml up -d dev`，之后 `... exec dev bash -lc "cd /workspace/vulnweaver/code && ..."` 跑 pytest/ruff/pyright 与栈内 E2E（control-plane 直达 api/postgres）；注意 `.venv` 属主须为 dev 用户(1000)。
4. **长线下一块**：记忆（T48）+续跑（T47）已就位；候选方向：agent 主导的 fuzz 战役引导（verification_request 结构化并驱动 FuzzJobScheduler 定向）、Q-025 根因修复。
4. 分支清理已完成（2026-09-28）：`feat/unpacking-toolchain` 合并入 main 并推送；本地仅剩 `main`（worktree `课设-worktree-fe-opts` 已随分支清理移除）；远程删除 13 个已合并/陈旧分支，保留未合并的 `demo/enrich-fixtures`、`feat/demo-final`（来历为演示用途，未动）。
5. 首跑注册的 API 账号 `vw-e2e`（密码在测试脚本常量中）仅用于联调，正式使用时建议改密或换账号。
