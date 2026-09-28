# ADR-030：项目级调查记忆——审计智能体的跨任务结论积累

- 状态：已接受
- 日期：2026-09-28
- 相关：ADR-027（智能体驱动审计）、ADR-029（审计检查点与断点续跑）

## 背景

"agent 主导 + 长线作战"的两个已就位前提：审计由智能体调查循环驱动、扫描器输出只是待确认线索（ADR-027）；单次调查崩溃/接管可续跑（ADR-029）。仍缺的一块：**每个任务都是失忆重启**——同项目上一次调查证实了什么、哪些候选位置锚定失败、覆盖到哪一步，对下一次审计完全不可见。同一个扫描器线索在新任务里重新触发时，智能体必须重新读代码重新判断，长线作战无从谈起。

## 决策

### 1. 记忆是 agent 自己的结论，不是工具转储

`investigation_memory` 模块把一次审计结算时的三样东西持久化为项目级记忆文档：**已锚定的候选 Finding**（cwe/位置/理由）、**锚定失败的候选位置**（模型报了但索引里不存在——除非有新证据否则不要再报）、**调查轨迹摘要与覆盖状态**（completed 标志 + 步骤摘要）。刻意不存原始工具输出：记忆的价值在判断（"这个线索查过了、不成立"），工具结果永远可以重新生成。

### 2. 一个项目一条记忆工件，版本链即时间线

记忆存为每项目一个 DERIVED 工件（`format: investigation-memory`），每次审计追加一个版本（以 run_id 派生确定性 id）。装载取最近 3 版，`memory_context_entry` 截断到有界切片进入审计上下文的 `prior_investigations`。写入失败降级为告警——记忆是加速器，绝不是审计的前置条件。

### 3. 提示词教智能体"基于自己过去的结论继续"

审计指令新增 Investigation memory 段：既往发现已入库不必重复报告、被弃位置无新证据不得再报、把轮次花在记忆显示未探索的线索上。与 ADR-029 的 Resuming 段（同一调查的中断恢复）互补：一个是"跨任务记忆"，一个是"跨崩溃记忆"。

### 4. 默认启用

`SemanticAuditor` 默认构造 `DatabaseInvestigationMemory`；不需要额外接线，任何部署（含 worker 镜像）开箱即有跨任务记忆。

## 后果

- 每次审计多一次 CAS 写 + 一行工件版本；装载为最近 3 版有界文档。成本可忽略，换来模型上下文中的"昨日结论"。
- 记忆文档是内部形状（schema_version 1.0.0），不走公共契约，仅同版本代码消费。
- 丢弃候选（dropped_documents）此前只计数不保留，本次随投影结果一并返回——它们正是"不要再犯"的记忆原料。
- dev container（compose.dev.yaml 的 `dev` 服务）本期起作为门禁标准执行环境：`docker compose -f compose.yaml -f compose.dev.yaml exec dev ...` 内跑 pytest/ruff/pyright 与栈内 E2E（control-plane 可达 api 与 postgres）。

## 验证

dev container（栈内 PostgreSQL 实跑）：`tests/orchestrator` + `tests/binary_analysis` **152 passed / 1 skipped**（新增 4 用例：记忆文档边界与形状、容错切片、写读往返与排序、既往结论/被弃位置进入下一次审计的模型上下文 + 审计回写自身结论）；ruff 通过；pyright **0 errors**。栈内 E2E（`scripts/e2e_investigation_memory.py`）：同项目连续两个任务全部 succeeded，项目出现 `investigation-memory` 工件且 **每任务一版共 2 版**。
