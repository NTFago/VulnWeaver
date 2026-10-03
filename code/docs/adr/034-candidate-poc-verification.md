# ADR-034: 候选阶段 PoC 自动复现验证

日期：2026-09-30
状态：设计决策已接受；当前实现受阻（2026-10-03 代码复核）

> **实现勘误（2026-10-03）**：下文“决策”“信任边界”和“后果”记载原设计意图与当时的局部测试结论，不代表真实闭环已成立。代码证据与验收入口见 [`../code-review-2026-10-03.md`](../code-review-2026-10-03.md) 的 CR-01/02/03/04。当前自动生成脚本被装入 JSON，proof entrypoint 执行外层 JSON 表达式而不执行脚本；沙箱只拿到脚本，没有待验证样本；退出成功直接成为 `EXPLOITABLE`。PoC markers 虽写入证据，复核事实白名单却将其删除。认证类策略还要求没有自动推导来源的 `constraint_analysis`。因此不能依据本 ADR 将该能力标为已实现或已验证。

> **ADR-036 修复回访（2026-10-03）**：自动生成内容现为版本化 `ProofInvocation` 数据（目标函数路径和输入编码），模型不再提供可执行 Python；bundle 携带 finding ID、摘要绑定的原目标和输入，worker/复核核对目标绑定。该修复在本地分支 `fix/target-bound-verification`，静态检查通过，pytest 与真实 Runner 验收待运行；确认前仍按未验收处理。

> **main@2757f35 复核回访（2026-10-03）**：审查又发现 manifest 成员比较遗漏 manifest，以及目标代码与报告器同进程执行可伪造 observation。修复分支 `fix/proof-supervisor-boundary` 将每轮目标调用移入限时子进程、父进程独立写报告，worker 交叉核对报告和 bundle，并使 PoC/evidence 幂等原子落库。全量 Python 门禁 711 passed / 4 skipped、覆盖率 81.69%；真实 Runner 正反例 3 passed。当前 `verified_trigger` 的 `target_exception_attributed` 只表示可重复目标异常，PoC 结果映射为 `INCONCLUSIVE`，仅记录 `SUPPORTING` evidence，review 不推导漏洞确认事实。

## 背景

在此之前的动态验证闭环存在两个断点：

1. **投放时机**：自动 exploit 只处理 `CONFIRMED` Finding（红线 10），fuzz 统一投放要等 REVIEW 结算。模型报告的候选 Finding（`CANDIDATE`）没有"生成 PoC → 沙箱执行 → 用执行结果验证"的路径。
2. **事实推导**：`derive_established_facts` 只从 CRASH_RECORD / REPRODUCTION_RESULT 推导内存破坏类事实；注入类（`source_to_sink_path`、`protection_analysis`）与认证类（`behavior_difference`、`reachable_path`）没有工具证据推导来源，即使动态执行成功也永远到不了 `evaluate_confirmation` 的门槛。

用户目标是：模型找到可疑漏洞后，自动生成 PoC、在沙箱执行、用执行结果确认这是不是真实漏洞。

## 决策

1. **候选阶段 PoC = 复现验证，不是 exploit**。新增 `PocVerificationScheduler`（`packages/proof/auto_poc.py`）：CANDIDATE Finding + 项目 `exploit_validation_enabled` 时投放一个 PROOF Job（幂等键 `poc_verification:<finding_id>`，每个 Finding 一生一次）。`ExploitScriptGenerator` 只生成契约约束的 `ProofInvocation`，不生成或执行任意模型代码。红线 10（exploit Job 只处理 confirmed）不放宽。
2. **历史标记协议（已停用）**：旧版 PoC 脚本打印 `POC_MARKERS: {json}`，proof executor 曾把模型自报内容登记为 STRONG 证据。2026-10-03 按 ADR-036 暂停该证据提升；无目标绑定和独立验证器时，marker 只能视为不可信脚本输出，不会产生 `POC_VERIFICATION_RESULT` 或触发确认。
3. **事实推导**：`derive_established_facts` 从 STRONG + reproducible 的 `POC_VERIFICATION_RESULT` 推导：通用 `minimal_reproduction`；注入类 `source_to_sink_path`（须 sink_reached + 具体 source/sink）与 `protection_analysis`；认证类 `behavior_difference` + `reachable_path`。
4. **确认仍走独立复核**。证据落地后由既有 PROOF 结算 → 证据触发定向 re-review（revision id）路径自动重开复核；confirmed 仍只能由 `FindingReviewGate`/`evaluate_confirmation` 依据工具产生的事实裁决。"模型不能自我确认"红线不变。
5. **契约与存储**：`EvidenceType` 枚举新增 `poc_verification_result`（TS/Python 同步再生成）；迁移 `0021` 放开 `evidence.type` CHECK 约束（原生 SQL，规避 alembic 命名约定二次包装）。

## 信任边界（已声明的残余风险）

2026-10-03 复核结论：本节所称“真实沙箱对真实样本运行”目前没有代码支持，且还存在上述执行/结果映射断点；它不是已生效的风险缓解措施。必须先修复 CR-01/02，再重新评估模型脚本自报 marker 的可信度。

标记由模型生成的脚本打印，理论上存在"打了标记但未真正触发漏洞"的伪造空间。接受的缓解：

- 标记只在**真实沙箱对真实样本运行**后由 harness 从 stdout 捕获，且仅 `COMPLETED`（退出码 0）的运行可产生 STRONG 证据；
- `run_log_ref` 落 CAS，复核（人/模型）可审计完整执行日志；
- 最终确认仍需独立上下文 re-review 同意——模型自我报告只产生证据，不产生结论。

这与"模型自我确认"的本质区别：模型只能提供**可被审计、可被驳回**的证据输入，裁决权在隔离的复核通道。

## 后果

**当前实现状态**：以下为原决策期望的后果；自动验证闭环现为受阻，解除条件为“脚本真实执行、样本版本作为受控输入、客观判据、marker 到复核事实完整传递、真实 runner 正反例测试”。

- 注入/认证/内存破坏三类候选 Finding 都有了自动动态验证闭环：候选 → PoC → 沙箱执行 → 证据 → 定向 re-review → （可能）confirmed → exploit。
- 每个候选 Finding 至多一次 PoC 运行，执行量受项目开关、proof 镜像 pin、脚本安全校验三重门控。
- 未配 `PROOF_TOOL_IMAGE_DIGEST` 时整条链路静默关闭（与自动 exploit 同门槛）。
