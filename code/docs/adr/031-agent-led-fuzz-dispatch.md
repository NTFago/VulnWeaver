# ADR-031：智能体引导的动态验证投放

- 状态：已接受
- 日期：2026-09-28
- 相关：ADR-027（智能体驱动审计）、ADR-029（检查点续跑）、ADR-030（调查记忆）、T32（Fuzz 链路）

## 背景

"agent 主导"长期缺的一环：审计智能体早就能在 `finding-report` 里声明 `verification_request: fuzz`（"这个问题读代码定不了，需要动态证明"），但该请求落地后只是一条 CONTEXTUAL、weight 0 的溯源证据——**对系统行为零影响**。fuzz 战役实际由 review 结算钩子统一触发：对所有非误报 Finding 一视同仁地投递（T32），agent 的判断不参与"打哪里、先打谁"的决策。智能体提出了定向需求，系统却按固定大水漫灌执行——这与"agent 主导、工具只是执行手"的定位相反。

另一处确认的残留（记录未实施）：静态扫描器的 diagnostics 仍在 `StaticFindingProjector` 直接落库为 `CANDIDATE` Finding，与智能体产出并行进入评审。`static-leads` 调查工具恰恰从这些 Finding 行读取线索，拆掉"工具→Finding"需要先把线索存储迁到证据层——留作下一个变更，本轮不动。

## 决策

### 1. agent 的 fuzz 请求即刻投放

`_project` 投影时额外返回 agent 显式标记 `verification_request == "fuzz"` 且锚定成功的 Finding id 列表。审计结算时（`_dispatch_agent_fuzz`）在项目开启动态验证（`exploit_validation_enabled`，与 T32/exploit 同一开关）的前提下，立即经 `FuzzJobScheduler.schedule_finding_in_transaction` 为它们投放 fuzz Job——**早于 review**。调度器的确定性幂等 id（按 finding_id 派生）保证随后 review 结算的统一投递自动去重。

投放门禁层层保留：项目 opt-in（agent 引导 ≠ agent 授权）、调度器内的有界目标解析（只打锚定工件、harness 检查）、沙箱隔离（禁网/非 root/一次性）原样不动。

### 2. 每审计上限 4 次

`_MAX_AGENT_FUZZ_DISPATCHES = 4`：动态执行昂贵，请求信号的本意是"读代码定不了"——这类位置天然集中在少数候选上。超出上限的请求仍记入证据链（溯源不变），只是不投放。

### 3. 失败降级

投放环节任何异常只告警（`agent_fuzz_dispatch_failed`），审计本身照常结算——引导是加速器，不是审计的前置条件（与 ADR-030 记忆、ADR-029 检查点同一纪律）。

### 4. 提示词同步

`verification_request=fuzz` 的语义从"登记一个愿望"变为"发起一场有界战役"：提示词明确告知请求会立即启动沙箱 fuzz、每审计至多数次、要花在崩溃能真正定案的位置上——智能体必须为每次请求承担选择责任。

## 后果

- 动态验证的时序从"review 之后统一扫"变为"agent 判断优先、review 之后兜底扫"：agent 请求的位置提前拿到崩溃证据，复核修订（ADR-027 §4）随之更早携带动态事实。
- `SemanticAuditor` 新增可选 `fuzz_dispatcher`；worker 装配经 `DeferredFuzzDispatcher` 持有器桥接装配顺序（fuzz scheduler 依赖同一步构建的 model gateway，审计器先行构造），装配完成后 `set` 注入；测试注入录制桩。
- 扫描器 diagnostics 直接落 Finding 的拆解（证据化 + 线索存储迁移）是"agent 主导"的下一刀，设计要点已记录。

## 验证

dev container（栈内 PostgreSQL 实跑）：新增 `tests/orchestrator/test_agent_fuzz_steering.py` 2 用例——仅 agent 显式请求（且锚定成功）的 Finding 被投放、未开启 opt-in 时零投放；`tests/orchestrator` + `tests/binary_analysis` 全量回归通过；ruff 通过；pyright 0 errors。
