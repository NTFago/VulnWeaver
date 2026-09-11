# DEVELOPMENT STATUS

> 动态交接台账。稳定规则见 `AGENTS.md`；架构和验收标准分别见《系统架构设计与技术选型.md》《系统实现模块拆分.md》。

更新时间：2026-09-11（Asia/Shanghai）

## 当前状态

- 项目：VulnWeaver（漏洞织鉴）。
- 当前主线：T45 二进制脱壳链路修复。
- 当前分支：`feat/t45-binary-unpacking-chain`。
- 分支占用：`feat/t45-binary-unpacking-chain` 的改动已完成并提交，工作树干净，待提 PR。
- 并行 worktree：`课设-worktree-fe-opts` 使用 `feat/frontend-delete-and-token-budget`，对应 T43。
- 本次维护：T45 改动已就绪；门禁 551 passed / 5 skipped、ruff 与 pyright 干净、前端 13 passed。

## 开发进度

| 任务 | 状态 | 负责人/分支 | 当前事实 | 下一步 |
|---|---|---|---|---|
| T45 二进制脱壳链路修复 | 待验证 | 分支使用者 / `feat/t45-binary-unpacking-chain` | 修复四处缺陷：①`BinaryFactsAdapter` 丢弃 `analyzed_path` 而用加壳输入（沙箱分析的从来不是脱壳文件）；②壳识别只认段名而真实 UPX 会删掉段表；③Ghidra 地址字段按镜像基址归一化但操作数仍是原地址空间，导致分支目标全部落空、CFG 断裂；④Java 导出的 `xrefs` 硬编码为空，跳转表目标丢失，dispatcher 无出边。函数重构改以 Ghidra 为主来源，从 strip 过的脱壳镜像恢复出正确函数边界；平坦化判据改为「宽扇出且会被重新进入」，真实样本 score=0.700、同镜像其余函数 0.000 | 剩自定义壳脱壳（angr 模拟 stub + 重建 ELF）与部署栈端到端审计链路 |
| T45-A 取消循环 token 预算 | 待验证 | 分支使用者 / `feat/t45-binary-unpacking-chain` | `AgentLoopBudget.max_model_tokens`（默认 200_000，即上下文窗口的数字）把单次调用的上下文窗口当成了多轮调查的累计上限，超限即 `loop_model_token_budget_exhausted` 截断调查；已删除该字段与硬停，用量仍累计上报。上下文窗口（`context_window_tokens`）与单次输出上限（`max_output_tokens`）是两个不同概念，均未改动；前端任务表单的 Token 预算输入同步移除 | 部署后确认审计循环不再被 token 截断 |
| T43 删除项目/任务与任务级 token 预算 | 待验证 | ZCode / `feat/frontend-delete-and-token-budget` | 删除 API、级联删除、终态任务限制和 `max_model_tokens` 已实现 | 全量门禁、真实浏览器回归、合并部署 |
| T42 任务详情双栏对齐 | 已完成 | Codex / `fix/task-panel-alignment` | 桌面双栏同高，窄屏恢复单列 | 无；随 Web 镜像发布 |
| WEB-INTEGRATE 中文审计工作台 | 已完成 | Codex | 工作台、轨迹、失败说明、报告中心和任务隔离已整合 | 发布前做真实部署 E2E |
| T20/T21/T22/T33 全链路与报告 | 待验证 | Codex | 代码、定向回放和部分浏览器链路已通过 | 在部署环境完成 Proof→报告→浏览器下载全链路 |
| T27/T28/T29/T30/T31/T32 课设能力补齐 | 待验证 | 多分支 | 规划、二进制分析、解混淆、语义审计、关键逻辑、利用和 Fuzz 链路已实现或完成定向验证 | 补真实模型、固定镜像和教学样本 E2E |

已完成的基础任务 T01-T19、T23-T26，以及 T35-T42 的具体历史记录不在本台账重复展开；需要时以 Git 历史、PR 和 `code/docs/progress/` 为准。

## 当前问题

| ID | 状态 | 结论 |
|---|---|---|
| Q-003 | 待处理 | Windows 中文路径下不使用 editable 安装；质量门禁统一在 Linux Dev Container 执行。修改 `packages/` 后需重新执行 `uv sync --all-packages --no-editable`。 |
| Q-005 | 待处理 | 复核源码事实仍主要是有界片段和 PAIR 快照，复杂跨函数问题的召回率可能受影响。 |
| Q-009 | 待处理 | 课设差距已拆为 T25-T34；代码大多已实现，真实模型/工具/部署 E2E 仍需补齐。 |

## 当前阻碍点

当前没有阻碍。

T45 是“有人正在使用的分支”，不是阻碍；解除条件是该使用者完成代码修改或明确交接后，再进行测试、合并和状态更新。

## 已确认决策

- 动态样本、Fuzz、Proof 和 Exploit 只能经独立 Sandbox Runner 执行，默认禁网、非 root、只读输入。
- 控制面和执行面分离；普通 Worker 不挂载 Docker Socket。
- 原始工件不可变，派生工件保留摘要、父工件和生成配置。
- ADR-021：先完成必跑审计基线，再进行 Finding 驱动的复核和动态深审。
- ADR-025：`resource_budget` 仅作惰性簿记，不新增计算资源拒绝或收敛逻辑；沙箱隔离属性不变。
- D-002：Fuzz 默认使用任务输入工件作为种子，不新增契约字段。

## 最近验证

| 日期 | 验证 | 结果 |
|---|---|---|
| 2026-09-11 | 前端定向门禁 | 13 passed；Svelte/TypeScript 通过；Vite 构建成功；1600×1000 与 900×900 模拟浏览器回归通过。 |
| 2026-09-10 | 集成全量门禁 | Linux Dev Container：540 passed、5 skipped，覆盖率 81.71%；Ruff、Pyright、契约、TypeScript、Svelte 通过。跳过项为外部 Runner/Docker opt-in。 |
| 2026-09-10 | 二进制与 Fuzz 回放 | Ghidra/objdump/UPX、Fuzz 沙箱和队列链路已有真实或定向回放；真实 OLLVM `fla`、部分真实模型和部署 E2E 仍待验证。 |

## 下一步

1. T45 使用者完成 `analyzed_path` 修复并补定向测试；在其明确交接前不修改该分支代码。
2. T43 worktree 完成全量门禁和真实浏览器回归。
3. 配置真实模型及固定工具镜像，补 T27-T32 的教学样本 E2E。
4. 在独立部署环境完成 T20/T21/T22/T33 的 Proof→报告→浏览器下载回归。
5. PR #61、#59、#60 的 CI、评审、合并和部署按既有授权处理；本文件不代表已获合并授权。
