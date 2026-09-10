# 归档：最近完成记录（2026-09-09）

> 自 DEVELOPMENT_STATUS.md 第 8 节归档，遵循“只保留最近 10 条”规则。

| 日期 | 任务/变更 | 验证结果 | 后续工作 |
|---|---|---|---|
| 2026-09-09 | AGENTS.md 课设支撑性修订 | 对照课设功能要求审查开发规则：新增功能验收锚点、Dev Container 门禁约定、静态解析与运行样本边界澄清、教学漏洞样本规则、提示词资产管理和分支合并后清理规则；修正根目录文件清单与过期分支记录；已清理 7 个已合并本地功能分支和远程旧分支；纯文档修订，无代码行为变化 | 合并 PR #16 后继续按 T20/T21/T22 验收事项推进 |
| 2026-09-09 | PR 前质量检查修复（`4318939`） | Pyright 定位可观测性端点 9 处类型错误，修复 `list_after` 位置传参运行时 Bug、failure 窄化和 `_count_values` 类型，并新增带失败 Job 的 API 回归测试；Dev Container 全量门禁通过（322 passed、81.22%） | 合并 PR 后继续 T20/T21/T22 真实回放 |
| 2026-09-09 | 代码审查修复（Proof/Report，`6dfc0db`、`97115eb`） | `/code-review high --fix` 定位 7 处问题，已修复 5 处正确性缺陷并提交：Sandbox 状态 `is`→`==`、proof 输出文件名改为 `result.json`、移除报告版本过早读取、报告 job/幂等键按格式区分、调度器放行 pdf | Q-006/Q-007 两项待跟进 |
| 2026-09-09 | T22 任务可观测性摘要 | API 提供任务 Jobs、事件、Finding 状态和结构化失败码汇总，Web 任务页加载并展示 Job 状态汇总 | 浏览器全链路和最终验收报告 |
| 2026-09-09 | T22 事件载荷可观测性 | Web 事件时间线支持展开查看结构化 payload，便于追踪策略、Job 和任务状态变化 | 浏览器链路和最终验收报告 |
| 2026-09-09 | T20 Web Proof/Exploit 操作 | Finding 详情提供脚本引用、镜像摘要输入及 Proof 发起；仅 confirmed Finding 且项目开启利用验证时显示 Exploit | 真实 Runner HTTP 回放与策略拒绝验收 |
| 2026-09-09 | T20 Proof Job 发起接口 | API 新增 Finding Proof/Exploit Job 投递接口，接入 ProofRequest 校验、项目策略和 Outbox 调度 | Web 操作按钮与真实 Runner 回放 |
| 2026-09-09 | T22 Finding 证据链详情 | Web 点击 Finding 后加载证据关系和 Poc 记录并展示工具、强度、摘要和执行状态；Dev Container 内 Svelte 检查通过 | 浏览器完整任务链路和可观测性收口 |
| 2026-09-09 | T21 PDF 报告端到端接入 | API/Worker/Web 支持 PDF，Worker 通过临时文件调用 WeasyPrint 后写入 CAS；Dev Container 内 Web typecheck/build、Ruff 和 reporting 测试通过 | 真实数据库报告 Job 与浏览器回放 |
| 2026-09-09 | Q-006/Q-007 安全与事务修复（`feat/sprint-final-closeout`） | Proof/Exploit 的 `script_ref` 现按项目范围解析归属（同 digest 可跨项目登记，全局解析不安全）；ProofJobExecutor 拆分事务，沙箱 HTTP 调用不再占用 DB 连接。Dev Container 全量门禁通过：328 passed、覆盖率 81.40%，Ruff/Pyright/Svelte 0 错误 | 继续推进 T16/T18/T19/T20/T21/T22 真实环境验收 |
| 2026-09-09 | T20 无害 Proof/Exploit 容器回放（`d0bcac0`） | 固定 `vulnweaver-proof:fixed` 镜像在禁网、只读根、非 root、capabilities drop 和 no-new-privileges 下分别回放两个入口，均 exit 0 | 补齐带 CAS 工件的 HTTP Runner 回放；不执行真实利用 |
