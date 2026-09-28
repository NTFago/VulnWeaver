# ADR-029：审计调查的持久检查点与断点续跑

- 状态：已接受
- 日期：2026-09-28
- 相关：ADR-027（智能体驱动审计）、ADR-028（分层脱壳工具链）、ADR-025（惰性预算）

## 背景

长线分析的第一块拼图：一次真实样本的语义审计是有界调查循环（ADR-027，无轮次上限、墙钟兜底），单次可运行数十分钟。Worker 崩溃或租约被接管后，Job 重试会**从零重跑整个调查**——已花掉的模型调用、已执行的工具步骤、模型已报告的候选全部丢失。`agent_runs` 虽有逐轮进度快照（sink），但没有任何代码消费它来恢复执行；`orchestration_checkpoints` 表与仓储一直只有 orchestrator 的任务流初始节点在用。

配套的两个校准问题：审计 `deadline_seconds` 默认 1800s 是课设样本时代的取值（T45-B 实测 54 秒完成 5 个决策）；审计提示词存在一处历史补丁造成的文本损坏（一句话被拦腰插入另一句），且不含任何"恢复执行"语境。

## 决策

### 1. 循环进度回调 + 检查点落盘

`AgentLoop` 新增 `progress: Callable[[LoopProgress], Awaitable[None]]` 回调：每轮边界以 `RunStatus.RUNNING` 发射一次、终态再发射一次，载荷即循环的全部可恢复状态（决策历史、已执行步骤、本轮步骤、token 用量、工件引用、模型标签、轮号）。`CodeAuditAgent` 把它落成 `orchestration_checkpoints` 中 node 为 `semantic-audit-agent` 的检查点（state 含 `job_id`、`completed` 标记、已报告 Finding 的完整文档）；落盘失败仅告警，绝不阻断调查。

### 2. 按 Job 续跑，完成即封存

`AgentLoopRequest.resume: LoopResume` 以既往决策/步骤/末轮反馈为种子：模型下一轮的上下文从"中断前的最后一个观察"继续，已执行步骤不再执行（步骤产物与已报告 Finding 直接进入本次结果聚合），决策序号续接。检查点按 `job_id` 匹配——同一 Job 的重试 attempt 续跑；任务重跑（新 Job）从零开始。上一次正常收尾（`completed=true` 标记）的检查点永不重放。

跨 Job 的 Finding 驱动增量由既有机制承担：动态证据（fuzz/proof）结算后以证据派生的修订 id 只对受影响 Finding 重开复核（ADR-027 §4），与本检查点共同构成"崩溃不断线、新证据不重审全部"的增量深审。

### 3. 长线校准

- 审计循环默认 `deadline_seconds` 1800→**7200**（`AGENT_AUDIT_DEADLINE_SECONDS` 仍可覆盖）；二进制分析每工具命令超时默认 180→**600s**，与沙箱请求上限对齐。预算其余字段保持惰性簿记（ADR-025）不变。
- 审计提示词重写：修复损坏句；按"取证—工具契约—报告纪律—续跑—停止条件"分段；新增证据标准（rationale 必须点名函数/行/地址与数据流）与续跑语境（"上下文中的既往步骤已执行，勿重复"）。

## 后果

- 每轮一次额外检查点写入（步骤观察按 `max_observation_chars` 截断、总量封顶 256 步/64 Finding），成本可忽略；复跑在 DeepSeek 计费上省下的是整个前半程调查。
- 检查点 state 是内部形状（schema_version 1.0.0），不走公共契约——它只在同版本代码间消费。
- worker 现在显式构造 `PostgresCheckpointStore`；无数据库的本地跑（tests）用内存实现。

## 实测教训

- 提示词字符串经脚本改写时转义损坏直接导致 worker 崩溃循环（`SyntaxError`），而 docker build 不做语法检查。教训：任何 `packages/` 改动必须先过 ruff/ast 再 build 镜像——本轮已补此纪律。
- `ReconfigurableRunner` 热重载后 registry 与 profiles 状态可分叉（`sandbox.image_identity_mismatch`，重启即愈）——登记为 Q-025 待查根因。

## 验证

Linux 容器：`tests/orchestrator` + `tests/binary_analysis` 共 **90 passed / 57 skipped**（跳过为 PG/Docker opt-in；新增 5 用例：resume 种子历史且不重执行已完成步骤、LoopResume 一致性校验、progress 回调轮次/终态双发射、中断检查点续跑（栈内 PostgreSQL 实测，含崩溃前 Finding 存活与终态封存）、completed 检查点不重放）；ruff 通过；pyright 0 错误。部署栈内：真实 UPX 壳（指纹抹除）经 unipacker 的端到端与 XOR 壳回归双双全绿（`scripts/e2e_unipacker_chain.py` / `e2e_unpack_chain.py`），新提示词下 `semantic_audit` 真实模型审计成功。
