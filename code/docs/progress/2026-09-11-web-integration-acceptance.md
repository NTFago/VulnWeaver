# 中文审计工作台整合与验收

日期：2026-09-11。分支：`feat/web-audit-integration`。基线：`origin/main@3fcbe1e`；收尾时通过 `git ls-remote` 再次确认主线未变化。

## 集成边界

以 main 的既有功能为行为基准，保留 work7 `demo/frontend-zh@f45b248` 的五个提交和组件拆分。`9b4c544` 为有双方父提交的集成提交；没有用旧 App 整文件覆盖主线。原 `.worktree/task-frontend`、其他开发者 worktree、部署栈均未修改。

| 主线或 work7 能力 | 最终归属与处理 |
|---|---|
| DeepSeek / GLM 预设、上下文裁剪 | SettingsView 使用主线 providers，保留上下文、密钥保留/清除与档位配置；修复动态档位绑定导致预设按钮运行时报错 |
| 资源预算 UI 移除 | 项目与设置表单不再提供 CPU、内存、磁盘、进程或全局 Token 资源预算；保留主线 Fuzz 高级参数、超时、模型思考设置 |
| 上传过滤、样本折叠 | ProjectView 归并源码包/PE accept 配置、三项默认折叠与选择保留；异步版本载入后文件名响应式更新 |
| Ghidra 列表伪代码 | TaskView 兼容字符串及对象列表，保留可滚动函数工作台、调用关系、复核和标注 |
| 中文审计流程 | TaskPipeline 按唯一 Job 聚合；完成比例只表示已调度单元结束比例，失败、取消、等待许可和未执行分别展示 |
| 多智能体与事件流 | AgentPanel 展示真实角色、Job、尝试、决策、工具步骤、输入输出引用；EventStream 展示事件与载荷；周期刷新、断线补拉去重、指数退避、任务请求隔离 |
| 报告生成与下载 | ReportCenter 分 PDF、Markdown、SARIF 卡片；按格式显示作业状态/错误/下载；原专业报告后端保留，没有改写报告模板 |

## 后端只读投影

GPT-5.6 Terra high 子任务在 `.worktree/web-audit-backend` 完成 `688e2d6`、`0b997be`；整合分支对应 `94647d1`、`cc887d6`。

新增 `GET /api/tasks/{task_id}/audit-trail`，返回版本化 DTO，不修改数据库、任务调度、Worker 或确认门禁。只按生产入口、Job 类型、精确 run ID 和编码在 ID 中的 attempt 关联角色；跨类型、歧义和历史尝试均返回 unknown。无 attempt 的精确规则仅关联 Job，不猜尝试次数。工具观察未持久化时返回 `not_recorded`。

二进制处理记录只列真实 binary-import 作业与已登记产物。识别、去壳、反编译、解混淆没有独立持久化进度事件，因此未画成四个虚假“已完成”步骤。智能体之间只标识确实共享的输入输出引用，不据此声称存在调度依赖或漏洞已确认。

## 对抗性检查与修正

- 已结束 100% 不代表全部成功：部分完成任务仍展示失败数、原因和黄色状态。
- 误报不计入有效漏洞等级分布，候选不视为已确认。
- 未调度源码 Fuzz 不等于禁用；按项目设置、任务终态和真实 Job 判断。
- 后端不存在可安全重置的单 Job retry，失败结果不可变。“重新审计”复用相同输入版本创建新 Task，保留旧任务记录；没有添加空操作重试按钮。
- AgentRun 没有事件时仍周期刷新；合并重复事件并保持 sequence 顺序。慢请求复用在途读取，切换任务后旧返回值不能覆盖新任务。
- 主线表单样式在半宽面板/窄屏出现复核按钮溢出，改为按容器宽度折行，保持大屏对齐。

## 实际验证

所有质量门禁在 Linux Dev Container `vulnweaver-web-integration-dev` 执行。Python 运行时复用只读依赖目录，通过 PYTHONPATH 显式指向整合分支的全部 apps/packages 源码，避免误测旧安装副本。

| 检查 | 结果 |
|---|---|
| `python -m ruff check .` | 通过 |
| Pyright 1.1.413，指定 Linux Python | 0 errors / 0 warnings |
| `python packages/contracts/scripts/generate_contracts.py --check` | 无漂移 |
| `python -m pytest --cov --cov-report=term:skip-covered --cov-fail-under=80` | 540 passed / 5 skipped；81.71%；1 条既有 Starlette 弃用警告 |
| `pnpm run check:typescript` | TypeScript/Svelte 0 错误 0 警告；12 个前端回归通过 |
| `pnpm run build`（apps/web） | Vite 生产构建通过 |
| Playwright Chrome 桌面 1440×1000 | 预设与保存、规划档位编辑、上传类型过滤、折叠后保留选择、源码 success、二进制 partial、failed 后创建新任务、决策展开、列表伪代码、人工复核入口通过 |
| Playwright 三格式下载 | PDF/Markdown/SARIF 生成入口与下载扩展名通过 |
| Playwright 390×844 | 复核/标注/工作台/报告中心可操作，document.scrollWidth 未超视口 |

前端回归覆盖：唯一 Job 计数、许可等待、动态功能是否启用、部分成功、调度分母变化、取消、报告格式与历史产物、伪代码兼容、误报统计、未知智能体角色、真实共享引用、事件重放去重。

浏览器使用 `code/apps/web/tests/dev-fixtures.mjs` 的明确标注模拟数据与 tmp 中的 mock API，未调用真实模型、运行样本或写部署数据库。模拟下载只验证按钮/请求/文件名；真实 PDF/Markdown/SARIF 内容由 Python 报告测试验证。模拟服务不实现 WebSocket 握手，故浏览器产生预期的连接失败记录，此场景检查了恢复提示和定时刷新，不能替代真实 WebSocket 部署验收。

5 个跳过项是 4 个外部 Proof Runner HTTP 回放和 1 个 Docker runtime 集成；需要明确的 Runner URL、工件引用、镜像摘要或运行开关。本轮未重新执行真实模型到 Sandbox Runner 的部署 E2E，不将 T20/T21/T22 整体标为完成。

## 交接与本机产物

本集成包已实现、验证并逐逻辑提交；经用户授权，已推送并创建 [PR #61](https://github.com/NTFago/VulnWeaver/pull/61)，目标 main。尚未合并或部署。发布前应在实际部署环境用授权源码和 ELF 任务补跑事件、人工复核与报告下载全流程。

尚未覆盖的原始完整愿景：二进制子步骤实时事实、历史漏洞趋势、报告快照修订及单 Job 重试协议。这些需要进一步持久化/协议设计；本轮界面明确展示现有数据边界。

本 worktree 的 `tmp/main-App.svelte` 与 `tmp/main-app.css` 是整合前的主线备份。`tmp/audit-desktop.png`、`tmp/audit-mobile.png` 为验收截图；其他 tmp 文件是编辑辅助脚本、mock 服务和下载测试产物，均未纳入 Git，可在不再需要复查时删除。依赖缓存、构建 dist 均未提交。

## PR #61 冲突修复复验

同步 main@192660d（PR #62），保留派生产物过滤、运行中轨迹落库、审计收敛及未完成审计失败语义。前端复用现有请求隔离与恢复逻辑，统一为单套 4 秒轮询。新增派生产物不成为样本的回归测试。Linux 验证：Python 定向 54 passed，前端 13 passed；Ruff/Pyright/契约/Svelte/TypeScript/生产构建通过。本次未重跑全量或真实部署 E2E。冲突快照 `tmp/App-pr61-conflict.svelte` 未提交，可在复查后删除。
