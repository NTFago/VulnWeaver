# ADR-025：移除计算资源限制

- 日期：2026-09-11
- 状态：已接受（项目负责人的显式产品决策，取代 ADR-024 中与预算门禁相关的部分）
- 补充：ADR-024（资源预算与 ToolSpec 的一致性）、ADR-021（审计基线）
- 影响模块：M01、M02、M04、M05、M07、M09、M10、M13、M14、API、Web、部署配置

## 上下文

ADR-024 将项目预算、ToolSpec 与沙箱请求三方数值对齐，解决了"预算不一致导致任务静默失败"的问题，但保留了两层计算资源门禁：Policy Engine 的"工具规格 ≤ 项目预算"比较，以及沙箱运行器的容器配额（CPU / 内存 / PID 数 / tmpfs 大小 / 输出上限 / 规格超时拒绝）。

实践表明，这套机制的成本远高于收益：

1. **门禁持续制造失败路径**。Q-010 至 Q-015 六个缺陷全部源于预算机制自身的复杂度：默认值推导、下界校验、方向相反的收敛（clamp）、超时默认值与客户端上限冲突。每一处都曾经让整个分析链路不可用。
2. **部署方即信任方**。本系统的部署者就是分析样本的授权者（个人部署形态，ADR-022），对"自己愿意花多少算力"有完整判断力，不需要系统代为拒绝。
3. **模型上下文与计算资源是两回事**。真正需要"管理"的是模型上下文窗口：超窗请求此前被直接拒绝（`ModelOutputError`），失败发生在任务执行中途，且对用户不可解释。

## 决策

项目负责人的显式要求：**删除所有计算资源的限制**。据此：

1. **Policy Engine 不再比较预算**。`PolicyContext` 删除 `resource_budget` 字段；`_check_resources`（`resource_limit_exceeded` / `timeout_exceeded`）删除。安全边界（网络白名单、工件类别、宿主路径拒绝、审批要求）全部保留。
2. **沙箱容器不再设置计算资源配额**。`DockerCliRuntime` 停止传递 `--cpus`、`--memory`、`--pids-limit` 与 tmpfs `size=`；输出卷不再按请求磁盘预算限额（内核 tmpfs 默认上限仍然生效）。运行器删除 `_budget_within` 与"请求超时 > 规格超时"拒绝；`sandbox.output_limit_exceeded` 删除。运行请求的 `timeout_seconds` 保留——它是防止失控容器占用宿主的运维停止手段，不是配额。
3. **保留一条固定输出上限**（`MAX_SANDBOX_OUTPUT_BYTES = 8 GiB`）。它只保护共享 CAS 卷所在的宿主磁盘不被失控容器写满（同卷上有 PostgreSQL），数量级远高于任何合法工具产物。
4. **预算数据结构保留为惰性簿记**。公共契约 v1.0.0 的 `ResourceBudget`、Project/Task/Job 的 JSONB 列与 ToolSpec 的 `resource_limits` 声明均保留（版本化契约不破坏、历史可追溯），但没有任何执行路径读取它们做拒绝或收敛。`bounded_resource_budget` 删除；API 建项目时写入常量 `UNBOUNDED_RESOURCE_BUDGET`（`max_model_tokens=0`，即"模型输出不设上限"约定），客户端提供的预算值被忽略。`CreateTaskRequest.resource_budget` 改为可选，缺省继承项目行。
5. **模型 token 预算不再制造失败**。`review.model_budget_exhausted` / `semantic_audit.model_budget_exhausted` 删除：`max_model_tokens=0` 统一表示"不限输出"，调用侧传 `None` 给网关。智能体循环的轮次 / 步数 / 连续失败上限保留——它们是上下文与行为管理，不是计算资源配额。
6. **模型上下文改为自动裁剪**。网关新增 `_fit_context_window`：端点配置了 `context_window_tokens` 且粗估（4 字符/token）超窗时，从最大的消息开始按"保留头尾 + 截断标记"收敛到窗口内，并把 `context_window_trimmed` 决策写入 AgentRun，而不是抛错中止任务。回退（review）端点新增 `review_model_context_window_tokens` 产品设置。
7. **预设模型提供商**。设置页新增 DeepSeek、智谱 GLM 官方预设，一键填充请求地址、默认模型与上下文窗口；所有字段仍可手工修改。不引入模型映射、代理覆盖等 CC Switch 式的进阶功能。

## 后果

- 分析任务不再存在任何"预算不足被拒"的失败路径；Q-010～Q-015 这一类缺陷的根因被整体移除而非继续修补。
- 沙箱容器可以不受限地使用宿主 CPU / 内存 / 进程数；失控工作负载由请求超时与容器清理兜底，极端情况下可能拖慢宿主。这是本决策显式接受的风险，安全边界（禁网、非 root、只读根、capability 全移除、no-new-privileges、一次性环境、摘要钉扎）不受影响。
- `resource_budget` 字段在新代码中禁止新增强制读取；后续如需恢复任何限额，应基于新的 ADR 重新设计，而不是复活 Budget 门禁。
- `tests/api/test_budgets.py`、`tests/tool_runtime`、`tests/sandbox_runner`、`tests/proof`、`tests/fuzzing` 的预算门禁断言改写为"不设限/透传"断言，防止门禁回归。
