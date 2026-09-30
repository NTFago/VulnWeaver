# ADR-034: 候选阶段 PoC 自动复现验证

日期：2026-09-30
状态：已接受

## 背景

在此之前的动态验证闭环存在两个断点：

1. **投放时机**：自动 exploit 只处理 `CONFIRMED` Finding（红线 10），fuzz 统一投放要等 REVIEW 结算。模型报告的候选 Finding（`CANDIDATE`）没有"生成 PoC → 沙箱执行 → 用执行结果验证"的路径。
2. **事实推导**：`derive_established_facts` 只从 CRASH_RECORD / REPRODUCTION_RESULT 推导内存破坏类事实；注入类（`source_to_sink_path`、`protection_analysis`）与认证类（`behavior_difference`、`reachable_path`）没有工具证据推导来源，即使动态执行成功也永远到不了 `evaluate_confirmation` 的门槛。

用户目标是：模型找到可疑漏洞后，自动生成 PoC、在沙箱执行、用执行结果确认这是不是真实漏洞。

## 决策

1. **候选阶段 PoC = 复现验证，不是 exploit**。新增 `PocVerificationScheduler`（`packages/proof/auto_poc.py`）：CANDIDATE Finding + 项目 `exploit_validation_enabled` 时投放一个 PROOF Job（幂等键 `poc_verification:<finding_id>`，每个 Finding 一生一次）。脚本生成复用 `ExploitScriptGenerator`（新 baseline `poc_verification`），提示词要求最小复现、无利用后动作，仍强制过 `validate_generated_script` 全部禁止模式。红线 10（exploit Job 只处理 confirmed）不放宽。
2. **标记协议**：PoC 脚本最后打印一行 `POC_MARKERS: {json}`（`sink_reached` / `source` / `sink` / `protections_observed` / `behavior_difference`）。proof executor 从沙箱 stdout（经 CAS `run_log_ref`）解析并净化标记；运行 `COMPLETED` 且有标记行时落一条 `POC_VERIFICATION_RESULT` 证据（STRONG、SUPPORTS，`replay_recipe` 含 markers 与 run_log_ref），WorkerResult 携带 `evidence_ids`。
3. **事实推导**：`derive_established_facts` 从 STRONG + reproducible 的 `POC_VERIFICATION_RESULT` 推导：通用 `minimal_reproduction`；注入类 `source_to_sink_path`（须 sink_reached + 具体 source/sink）与 `protection_analysis`；认证类 `behavior_difference` + `reachable_path`。
4. **确认仍走独立复核**。证据落地后由既有 PROOF 结算 → 证据触发定向 re-review（revision id）路径自动重开复核；confirmed 仍只能由 `FindingReviewGate`/`evaluate_confirmation` 依据工具产生的事实裁决。"模型不能自我确认"红线不变。
5. **契约与存储**：`EvidenceType` 枚举新增 `poc_verification_result`（TS/Python 同步再生成）；迁移 `0021` 放开 `evidence.type` CHECK 约束（原生 SQL，规避 alembic 命名约定二次包装）。

## 信任边界（已声明的残余风险）

标记由模型生成的脚本打印，理论上存在"打了标记但未真正触发漏洞"的伪造空间。接受的缓解：

- 标记只在**真实沙箱对真实样本运行**后由 harness 从 stdout 捕获，且仅 `COMPLETED`（退出码 0）的运行可产生 STRONG 证据；
- `run_log_ref` 落 CAS，复核（人/模型）可审计完整执行日志；
- 最终确认仍需独立上下文 re-review 同意——模型自我报告只产生证据，不产生结论。

这与"模型自我确认"的本质区别：模型只能提供**可被审计、可被驳回**的证据输入，裁决权在隔离的复核通道。

## 后果

- 注入/认证/内存破坏三类候选 Finding 都有了自动动态验证闭环：候选 → PoC → 沙箱执行 → 证据 → 定向 re-review → （可能）confirmed → exploit。
- 每个候选 Finding 至多一次 PoC 运行，执行量受项目开关、proof 镜像 pin、脚本安全校验三重门控。
- 未配 `PROOF_TOOL_IMAGE_DIGEST` 时整条链路静默关闭（与自动 exploit 同门槛）。
