# 独立崩溃/利用 Oracle 立项评估（2026-10-04）

> ADR-036 阶段提案的配套评估。回答一个问题：在当前"Python 可调用目标 + bundle 绑定执行"的能力边界内，"能证明安全影响的独立崩溃/利用 oracle"应否立项、以何种形态立项、边界在哪里。评估以现有代码与测试为证据，不预设结论。

## 1. 现状与缺口

当前验证 oracle 覆盖两类可机器判定的事实，均由可信入口（supervisor）在隔离子进程边界上计算：

| Oracle | 机制 | 结论 | 已建立的事实 |
|---|---|---|---|
| `verified_trigger` | 目标子进程以退出码 10 结束且逐帧归属到目标代码对象，对照干净、重放稳定（`apps/proof-tool/vulnweaver-proof-entrypoint`） | PoC 结果恒为 `INCONCLUSIVE`，证据为 `SUPPORTING` | 目标可重复异常（诊断性，非安全影响） |
| `verified_behavior` | supervisor 摘要每轮有界输出；crafted≠control 且重放逐字节一致（CR-04 本轮落地） | 同上；注入/鉴权类经 worker 派生 STRONG 标记 | 输入依赖的确定性行为差 + 保护面枚举 + 约束绑定（鉴权） |

缺口：两者都不能区分"目标作者预期的异常/行为"与"攻击者可利用的内存破坏"。`FindingPolicy` 要求 memory-corruption 类确认具备 `repeatable_crash`/`controllable_input`/`matching_environment` 三事实，当前无任何独立来源能提供它们——内存破坏类 Finding 在此能力边界内**结构性不可确认**（保持候选是正确行为而非缺陷）。

## 2. 候选方案对比

### 方案 A：崩溃信号 oracle（faulthandler/信号级）

在 proof 子进程中启用 `faulthandler` 与 SIGSEGV/SIGABRT 捕获，把"解释器崩溃或 native 扩展崩溃"与"目标内 Python 异常"区分。解释器级崩溃（abort、段错误）对 C 扩展目标是真实的内存破坏信号。

- 优点：完全在现有 bundle 协议内；实现集中在 target-worker 与 observation 契约（新增 `crash_kind` 字段）；对带 C 扩展的样本立即有效。
- 缺点：纯 Python 目标永远到不了解释器崩溃——`MemoryError`、`RecursionError` 是解释器正常行为。覆盖率取决于样本是否含 native 扩展。
- 判据真实性：SIGSEGV 归属到目标进程即可主张 `repeatable_crash`；`controllable_input` 可由 crafted≠control + 崩溃输入重放共同支撑。**这是唯一能在不扩大目标边界的前提下部分闭合三事实的方案。**

### 方案 B：Sanitizer 运行时（native 目标，依赖 P1 BuildProfile）

对 C/C++ 目标以 ASan/UBSan 构建后执行 bundle 输入，以 sanitizer 报告为崩溃事实。

- 优点：业界标准答案，报告即证据；与 R3 真实项目闭环轨（FFmpeg/7-Zip）天然重合。
- 缺点：硬依赖尚未立项的 P1 BuildProfile（原项目构建/链接绑定、fuzz target 复用）；Python 目标完全不适用。
- 结论：**不应单独立项**，应作为 P1 闭环轨的组成部分。

### 方案 C：利用性差分 oracle（信息泄露/权限边界的语义断言）

在 `verified_behavior` 之上让模型声明"可观测影响断言"（如响应含越权数据），由 supervisor 机械验证输出满足断言。

- 缺点：断言语义由模型给出即引入模型解释通道，违反"模型解释不能单独确认"红线 8 的精神——它会把确认权变相交回模型。除非断言语言是固定 DSL 且由控制面求值，否则不应立项。
- 结论：**否决**，保留为长期研究方向。

## 3. 建议：方案 A 单独立项，方案 B 挂靠 P1

**建议采纳方案 A**，作为 ADR-036 下一阶段（P0.5）小步提案：

1. 契约：`VerificationRun` 增加 `crash_kind`（`none`/`python_exception`/`interpreter_signal`），`VerificationObservation` 增加顶层 `crash_kind` 聚合；`VerificationOutcome` 不新增枚举（崩溃事实由 reason 与 crash_kind 表达）。
2. worker 侧：`interpreter_signal` 且归属目标进程时，`evidence_from_observation` 的观测升级为可推导 `repeatable_crash` + `matching_environment` 的事实来源（新 observation 事实映射，走既有 `VERIFICATION_OBSERVATION` 通道）；`controllable_input` 仅在 crafted 输入重放一致时附带。
3. 信任边界不变：crash_kind 仍由 supervisor 从子进程退出状态计算，目标代码无法伪造（现有每轮隔离子进程 + 报告隔离已覆盖）。
4. 明确不主张：解释器信号不能证明可控性或可利用性——`PocResult` 保持 `INCONCLUSIVE`，利用验证仍走既有 exploit Job 门（confirmed + 项目显式开启）。

工作量估算：契约与生成物 ~0.5 天；entrypoint/worker/verifier ~1 天；正反例（含 faulthandler 教学样本）与 Runner 验收 ~1 天。方案 B 随 P1 BuildProfile 立项时一并设计，不在本提案内。

## 4. 风险与红线符合性

- 红线 4/5：全部执行仍在 Sandbox Runner 隔离环境内，无新执行形态。
- 红线 8：crash_kind 是机器事实；确认决策仍由 `FindingPolicy` 按事实集求值，模型 re-review 仍是提案方。
- 误报风险：把合法 abort 误判为漏洞崩溃的缓解是"归属到目标进程 + 对照干净 + 重放稳定"三条件齐备，且 PoC 结果不因 crash_kind 升级——影响只进入复核事实，不自动改写结论。
- 回滚：新字段全部可选，旧 observation 契约兼容读取。
