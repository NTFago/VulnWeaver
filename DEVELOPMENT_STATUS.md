# DEVELOPMENT STATUS

> 动态交接台账。稳定规则见 `AGENTS.md`；架构和验收标准分别见《系统架构设计与技术选型.md》《系统实现模块拆分.md》。

更新时间：2026-09-11（Asia/Shanghai）

## 当前状态

- 项目：VulnWeaver（漏洞织鉴）。
- 集成基线：`main`（`4d5acbf`），工作树干净；T43/T45 及后续修复（含 #70-#72）均已合并、重建镜像并重启部署栈。
- 并行 worktree：`课设-worktree-fe-opts` 使用 `feat/frontend-delete-and-token-budget`，对应 T43。
- 部署栈：全部容器 Up，`api`/`analysis-worker`/`orchestrator`/`web`/`binary-tools` 均为合并后重建的镜像。

## 开发进度

| 任务 | 状态 | 负责人/分支 | 当前事实 | 下一步 |
|---|---|---|---|---|
| T45 二进制脱壳链路修复 | 已完成 | Codex / PR #66 | 修复四处缺陷：①`BinaryFactsAdapter` 丢弃 `analyzed_path` 而用加壳输入，沙箱分析的从来不是脱壳文件；②壳识别只认段名，而真实 UPX 会删掉段表；③Ghidra 地址字段按镜像基址归一化、操作数仍是原地址空间，致分支目标全部落空、CFG 断裂；④Java 导出的 `xrefs` 硬编码为空，跳转表目标丢失、dispatcher 无出边。函数重构改以 Ghidra 为主来源，从 strip 过的脱壳镜像恢复出正确函数边界；平坦化判据改为「宽扇出**且**会被重新进入」。**部署栈端到端实测**：函数 0→17、`status` partial→complete、`analyzed_av` 指向脱壳版本、反混淆仅标记 `flattened_checksum`（0.700，同镜像其余 0.000） | 仅剩自定义壳脱壳 |
| T45-A 取消循环 token 预算 | 已完成 | Codex / PR #66 | 删除 `AgentLoopBudget.max_model_tokens` 与 `loop_model_token_budget_exhausted` 硬停——默认 200_000 把**单次调用的上下文窗口**当成了**多轮调查的累计上限**。用量仍累计上报。`context_window_tokens` 与单次 `max_output_tokens` 是两个不同概念，均未改动；前端任务表单的 Token 预算输入同步移除 | 无 |
| T45-B 循环改用时间约束 | 已完成 | Codex / PR #67 | 移除逆向规划写死的 2 轮上限（实测 54 秒 5 个决策即被砍断、回落固定管线）；补 `deadline_seconds` 兜底——此前全仓生产代码从未设置过它，去掉轮次上限后循环将无任何硬上界 | 观察真实任务耗时后校准取值 |
| T45-C 循环超时可配置 | 已完成 | Codex / PR #68 | 契约新增 `AgentLoopBudgets`，贯通域解析 → 设置 API → worker → 设置页；`0` 表示沿用部署默认值（解析器对所有预算项一律把非正值读作未设置），支持 `AGENT_*_DEADLINE_SECONDS` | 无 |
| T45-D 审计候选 ID 冲突 | 已完成 | Codex / PR #71 | 审计按 `(task, cwe_id, location)` 派生 Finding ID，而仓储把 `title`/`dataflow`/`fix_suggestion` 也算身份字段、不一致即抛 `EntityConflict`；同位置同 CWE 的不同候选因此撞 ID，异常无人捕获，整个审计 Job 死于无消息的 `worker.execution_error`。仓储拒绝合并是对的，故改为**逐候选捕获、计为 dropped、继续**。取消轮次上限后审计报出更多候选，才暴露这个组合 | 无 |
| T45-E worker 异常消息可诊断 | 已完成 | Codex / PR #70 | `worker.execution_error` 只记录 `exception_type`，**丢弃消息与 traceback**，两次线上失败都只能靠容器内手工复现定位。现增加 `exception_message`（截断 500 字符）。**该修复立刻见效**：下一次审计失败直接给出 `EntityConflict` + 原因，T45-D 由此定位 | 无 |
| T45-F PAIR 行归属被分析的镜像 | 已完成 | Codex / PR #72 | 函数 ID 本就含 `analyzed_artifact_version_id`，但行的 `artifact_version_id` 写的是上传工件，工作台又按工件查——三者不一致，每投一次任务就多一整套函数行（加壳样本累积到 68 行 / 16 个函数）。改法为**保持 ID、把列对齐**（8 处），工作台改为解析任务的被分析镜像（`binary-import` 结果的 `binary-analysis-result` 版本之 parent），并与源码管线的输入版本取并集。**历史数据已回填**：`pair_functions` 68 行、`pair_nodes` 816 行、`pair_edges` 364 行，执行量与 dry-run 逐表吻合 | `pair_raw` 未回填（见下一步） |
| T43 删除项目/任务与任务级 token 预算 | 已完成 | ZCode / PR #65 | 删除 API、级联删除、终态任务限制已实现并合并。**部署曾一度返回 405**：`api` 镜像自合并后从未重建，已重建并实测（405 → 401，路由存在） | 无 |
| T42 任务详情双栏对齐 | 已完成 | Codex / `fix/task-panel-alignment` | 桌面双栏同高，窄屏恢复单列 | 无 |
| WEB-INTEGRATE 中文审计工作台 | 已完成 | Codex | 工作台、轨迹、失败说明、报告中心和任务隔离已整合 | 发布前做真实部署 E2E |
| T20/T21/T22/T33 全链路与报告 | 待验证 | Codex | 代码、定向回放和部分浏览器链路已通过 | 在部署环境完成 Proof→报告→浏览器下载全链路 |
| T27-T32 课设能力补齐 | 待验证 | 多分支 | 规划、二进制分析、解混淆、语义审计、关键逻辑、利用和 Fuzz 链路已实现或完成定向验证 | 补真实模型、固定镜像和教学样本 E2E |

已完成的基础任务 T01-T19、T23-T26，以及 T35-T42 的具体历史记录不在本台账重复展开；需要时以 Git 历史、PR 和 `code/docs/progress/` 为准。

## 当前问题

| ID | 状态 | 结论 |
|---|---|---|
| Q-003 | 待处理 | Windows 中文路径下不使用 editable 安装；质量门禁统一在 Linux Dev Container 执行。修改 `packages/` 后需 `uv sync --all-packages --no-editable`，必要时加 `--reinstall`——不重装会**静默使用旧代码**，本轮两次据此误判测试结果。 |
| Q-005 | 待处理 | 复核源码事实仍主要是有界片段和 PAIR 快照，复杂跨函数问题的召回率可能受影响。 |
| Q-009 | 待处理 | 课设差距已拆为 T25-T34；代码大多已实现，真实模型/工具/部署 E2E 仍需补齐。 |
| Q-021 | 待处理 | **部署顺序陷阱**：worker 启动时缓存工具镜像摘要，镜像重建后必须**先重启 sandbox-runner、再重启 worker**；顺序反了不会当场报错，只在下次任务变成无消息的 `worker.execution_error`。 |
| Q-022 | 待处理 | worker 把执行器异常压成 `{"exception_type": …}`，**丢弃消息与 traceback**，只能靠容器内复现定位。 |
| Q-023 | 待处理 | Windows 工作区新建的脚本为 CRLF；`.gitattributes` 只在 commit/checkout 归一化工作树，容器内 `sh` 读 CRLF 直接报 `Illegal option -`。 |
| Q-024 | 待处理 | `pair_raw.artifact_version_id` 仍指向上传工件。它无 `location` 可推导，但 `object_ref` 能对上 `binary-analysis-result` 版本，取其 `parent_version_id` 即目标（4 行）。不影响工作台显示，但数据仍不一致。 |

## 当前阻碍点

当前没有阻碍。

## 已确认决策

- 动态样本、Fuzz、Proof 和 Exploit 只能经独立 Sandbox Runner 执行，默认禁网、非 root、只读输入。
- 控制面和执行面分离；普通 Worker 不挂载 Docker Socket。
- 原始工件不可变，派生工件保留摘要、父工件和生成配置。
- ADR-021：先完成必跑审计基线，再进行 Finding 驱动的复核和动态深审。
- ADR-025：`resource_budget` 仅作惰性簿记，不新增计算资源拒绝或收敛逻辑；沙箱隔离属性不变。
- ADR-027：审计循环不设规划轮次上限。T45-B 将同一原则推广到逆向规划，并以墙钟 deadline 作为唯一兜底。
- D-002：Fuzz 默认使用任务输入工件作为种子，不新增契约字段。

## 最近验证

| 日期 | 验证 | 结果 |
|---|---|---|
| 2026-09-11 | T45 部署栈端到端（真实投递 UPX 加壳样本） | `binary-import`/`semantic_audit`/`review`/`report` 全部 succeeded；`functions` 0→17、`basic_blocks` 37、`xrefs` 55、`status` partial→complete；`upx-unpacked-binary` 派生物摘要与加壳前逐字节一致（`da691578…`）；反混淆仅标记 `FUN_00101138`（`flattened_checksum`，0.700）。 |
| 2026-09-11 | T45-A/B/C 全量门禁 | Linux Dev Container：554 passed / 5 skipped；`ruff check .` 通过；`pyright` 0 errors；契约 `--check` 无漂移；前端 13 passed、`svelte-check` 0 错误、Vite 构建成功。 |
| 2026-09-11 | 删除接口修复实测 | 重建 `api` 镜像后 `DELETE /api/projects|tasks/{id}` 由 405 变为 401（路由存在、仅缺认证）。 |
| 2026-09-11 | 前端定向门禁 | 13 passed；Svelte/TypeScript 通过；Vite 构建成功；1600×1000 与 900×900 模拟浏览器回归通过。 |
| 2026-09-10 | 集成全量门禁 | Linux Dev Container：540 passed、5 skipped，覆盖率 81.71%；Ruff、Pyright、契约、TypeScript、Svelte 通过。跳过项为外部 Runner/Docker opt-in。 |
| 2026-09-10 | 二进制与 Fuzz 回放 | Ghidra/objdump/UPX、Fuzz 沙箱和队列链路已有真实或定向回放；真实 OLLVM `fla`、部分真实模型和部署 E2E 仍待验证。 |

## 下一步

1. **回填 `pair_raw`**：SQL 已 dry-run 验证（4 行受影响，物料为 `object_ref` → `binary-analysis-result` 版本的 parent）。需用户点名该表后再执行。
2. **自定义壳脱壳**：目标明确要求，目前完全未实现，是链路唯一缺口。建议顺序——先做脱壳器（高熵可执行区的 XOR 密钥恢复 + `objcopy` 包装为 ELF），它可独立验证；样本侧再处理入口 ABI（`_start` 需要初始栈与 `%rdx`，stub 必须尾跳而非 `call`）。
2. 校准 T45-B 的 deadline 取值（900s/1800s 按观测耗时 16×/20× 取，未在真实负载下验证）。
3. 实现 Q-021/Q-022 的修复：摘要按需解析 + 异常消息落库。
4. T43 worktree 完成真实浏览器回归。
5. 配置真实模型及固定工具镜像，补 T27-T32 的教学样本 E2E。
6. 在独立部署环境完成 T20/T21/T22/T33 的 Proof→报告→浏览器下载回归。
7. 远程分支 `origin/feat/t45-binary-unpacking-chain` 已被 rebase 后的后续合并取代，属陈旧分支；删除远程分支改变共享状态，需用户确认。
