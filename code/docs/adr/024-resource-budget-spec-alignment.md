# ADR-024：资源预算与 ToolSpec 的一致性

- 日期：2026-09-10
- 状态：已接受
- 补充：ADR-011（资源预算以 JSONB 存储）
- 影响模块：M01、M02、M04、M09、M10、M13、M14、部署配置

## 上下文

策略门禁与沙箱执行都按"请求预算不得超过工具规格"判定，但两侧的数值来源互不校对，导致部署后无法完成任何一次分析：

1. **前端默认预算低于已发布的 ToolSpec**。`App.svelte` 硬编码 `cpu_millis: 2000`，而 `deploy/tool-specs/binary-import.json` 声明 8000、`semgrep.json` 与 `cppcheck.json` 声明 4000。Policy Engine（`policy.py`）比较 `工具规格 ≤ 项目预算`，于是二进制任务在建初始 Job 之前就被拒（`initial_job_policy_denied` / `resource_limit_exceeded`），源码任务则在 semgrep/cppcheck 阶段被拒。项目预算没有更新端点，用户无法自救。
2. **ToolSpec 数值与运行时实际不符**。`binary-import.json` 声明 `cpu 8000 / memory 1 GiB`，而运行时真正使用的配置是 `cpu 4000 / memory 3 GiB`——`docs/binary-analysis-runtime.md` 与 `packages/binary-analysis/.../tools.py` 的 `_sandbox_budget()`、以及沙箱运行器注册 `binary-facts` 时的 `BINARY_CPU_MILLIS` / `BINARY_MEMORY_BYTES` 默认值三处一致。全仓没有任何文档记录 8000/1 GiB 的来源，且 1 GiB 比运行时的实际需求更小，作为门禁阈值既过严（CPU）又过松（内存）。
3. **proof/fuzz 请求的预算方向相反**。沙箱运行器要求 `请求 ≤ 规格`（`runner.py` 的 `_budget_within`，逐项比较 7 个字段），而 UI 把**整个项目预算**当作 proof 请求的预算下发；proof-tool 的规格只有 `cpu 1000 / memory 256 MiB / timeout 120`，因此任何项目预算都会让 Proof/Exploit 必然失败于 `sandbox.resource_budget_exceeded`。模糊测试同理：`FuzzExecutionService` 只把 `timeout_seconds` 收敛到规格，`resource_budget` 原样透传。

## 决策

1. **校准 ToolSpec 到运行时实际值**：`deploy/tool-specs/binary-import.json` 的 `resource_limits` 改为 `cpu 4000 / memory 3 GiB / disk 1 GiB / timeout 600`，与 `docs/binary-analysis-runtime.md`、`binary-analysis` 的 `_sandbox_budget()` 和运行器 `_resource_budget()` 的默认值一致。该规格是初始 Job 的策略门禁阈值，不是执行预算；执行预算仍由运行器注册的 `binary-facts` 规格独立约束。
2. **默认预算由服务端按已注册规格推导**：`POST /api/projects` 未提供 `resource_budget` 时，API 取各规格 `resource_limits` 的逐项最大值作为默认值；显式提供但低于该下界时以结构化错误 `resource_budget_below_tool_requirements` 拒绝，并在消息中点名具体资源项。前端不再持有魔法常量，项目表单可展开填写 7 项预算。
3. **动态执行额度纳入默认值**：`deploy/tool-specs` 中的规格不声明动态运行（动态工具由沙箱运行器注册），故默认预算的 `max_dynamic_runs` 取 `max(下界, 1)`。项目开启 `exploit_validation_enabled` 但预算不允许动态运行时，建项目即被拒（`resource_budget_blocks_dynamic_runs`），避免 Proof/Exploit 在运行期才失败。
4. **请求侧按规格收敛**：新增 `vulnweaver_tool_runtime.bounded_resource_budget`，作为"请求预算按规格逐项取小"的唯一实现。proof 执行器按注入的 proof-tool 规格收敛，模糊测试执行器按已解析的 afl-casr 规格收敛，源码静态阶段原本的私有 `_bounded_budget` 改为复用同一实现。运行器侧的"拒绝超限请求"判定不变——收敛必须发生在调用方，运行器不静默削减安全相关资源请求。
5. **API 需要规格来源**：`api` 服务新增 `vulnweaver-tool-runtime` 依赖、`TOOL_SPEC_DIRECTORY` 环境变量与 `./deploy/tool-specs` 只读挂载。未配置该目录时预算不可校验，此时 `resource_budget` 仍为必填。

## 后果

- 从 Web UI 新建的项目开箱即可跑通二进制与源码流水线；预算不合理时在建项目阶段就能拿到点名到具体资源项的明确错误，而不是任务静默失败。
- ToolSpec 与运行时数值重新单一化，`docs/binary-analysis-runtime.md` 成为这两个数字的权威出处。
- 放宽 `binary-import` 的 CPU 门禁（8000 → 4000）是对策略阈值的调整，但不改变沙箱隔离：实际执行预算、禁网、非 root、只读根与资源上限仍由运行器注册的规格与请求共同约束。
- proof/fuzz 的请求预算被收敛到工具规格内，Proof/Exploit 与模糊测试不再因预算方向相反而必然失败。
- `tests/api/test_budgets.py` 直接加载真实 `deploy/tool-specs` 并断言默认预算覆盖全部规格，防止两侧再次漂移。
