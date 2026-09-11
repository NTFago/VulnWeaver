# ADR-026：审计由智能体调查驱动，证据事实由证据推导

- 状态：已接受
- 日期：2026-09-11
- 相关：ADR-021（审计计划与深审）、ADR-025（移除计算资源限制）

## 背景

课设要求「基于大模型智能体的软件漏洞挖掘系统……智能体是主力，工具只是参考」。对照代码事实，审计环节离这一要求有本质差距，并伴随两处阻断核心链路的缺陷。只读核查确认：

1. **审计不是智能体行为。** `SemanticAuditor.audit()` 是一次性模型调用：取最多 256 个 PAIR 函数、拼上被截断的代码片段、单次 `complete_structured(output_contract="SemanticAuditReport")` 后直接投影。模型不能决定审什么函数、不能读取某个函数的完整实现、不能跟踪调用链、不能就不确定性继续取证。静态扫描器先跑并直接投影为 Finding，审计只在后面补一轮——正好与「工具只是参考」相反。
2. **二进制伪代码从未到达模型。** `semantic_audit` 以 `isinstance(pseudocode, str)` 读取 `PairFunction.attributes["pseudocode"]`，而二进制导入器写入的是 `BinaryPseudocode` **列表**。判断恒假，二进制函数静默退化为「无代码可审」——课设「基于二进制反编译后的可读代码/伪代码开展漏洞检测」因此落空。
3. **confirmed 事实上不可达。** `FindingPolicy` 为各 Finding 类别声明了必需事实，但全仓没有任何代码把它们从证据中推导出来：`FindingReviewGate` 只合成 `independent_review_agreement` 与 `independent_tool_evidence`。同时，已结算的 fuzz/proof Job 不会重新触发复核，其挂接的崩溃证据落在那唯一一次复核之后、永远不会被消费。结果是内存破坏/注入/认证类 Finding 永远无法 confirmed，`evaluate_exploit_eligibility` 恒拒绝，课设的「漏洞自动利用模块」没有可达输入。

## 决策

### 1. 审计改为「规划—执行—观察」调查循环

审计复用既有的 `AgentLoop`，由它把模型输出转成策略校验过的 `ActionPlan`。模型拿到一组**只读调查工具**而非一次性函数转储：

| 工具 | 作用 |
|---|---|
| `code-function-list` | 按路径/名称检索索引中的函数 |
| `code-function-read` | 读取指定函数的源码摘录**或伪代码**、签名与邻域摘要 |
| `code-search` | 对源码或二进制字符串做正则检索（此前全仓无任何检索原语） |
| `call-neighborhood` | 取 caller/callee 与调用边 |
| `artifact-facts` | 读导入表、字符串、段表、包壳/混淆评估 |
| `static-leads` | 读扫描器线索 |
| `critical-logic` | 读认证/加解密/注册候选与判定 |
| `finding-report` | 登记候选 Finding |

工具是进程内 `ToolSpec`，因此每个调查步骤仍经 `PolicyEngine` 校验，并作为 `DecisionRecord` 记入一条聚合 `AgentRun`——调查轨迹因此可追溯、可在前端展示。静态扫描器输出降级为**线索**：进入循环上下文，由模型逐条确认或否定，不再直接等于结论。

模型未配置或循环降级时，回落既有一次性提示路径，保证 ADR-021 的审计基线仍然完成、`NO_FINDINGS` 门禁不因新路径而卡死。

### 2. 候选的信任边界不变

模型报告的候选在被锚定到不可变 PAIR 索引之前不落库，无法锚定的位置/地址一律丢弃并计数。落库后仍走既有独立复核与 `FindingPolicy` 门禁。**本次决策扩大的是发现面，不是信任面。**

### 3. 确认事实由证据推导

新增 `derive_established_facts`：仅从 `SUPPORTS` 关系、且强度为 `STRONG`、可复现、非 `MODEL_EXPLANATION` 的证据推导类别事实。判据本身不变（类别事实齐全 + 至少一条非模型强可复现证据），变的是「事实从证据中来」这件本来就该发生的事。

映射刻意保守：

- `CRASH_RECORD`（强、可复现）→ `repeatable_crash`、`matching_environment`；已物化崩溃输入 → `controllable_input`。
- `REPRODUCTION_RESULT`（强、可复现）→ `minimal_reproduction`。
- 崩溃**不**推导 `source_to_sink_path`、`reachable_path` 等——注入与业务逻辑类 Finding 不会仅凭一次崩溃被确认。

### 4. 动态验证的证据可重新触发复核

`ReviewJobScheduler.schedule_in_transaction` 接受可选 `revision`：首次复核沿用原确定性 id（幂等不变），带修订 id 的复核用于「复核之后新到的证据」。结算钩子在 fuzz/proof Job 结算且确实挂接了新证据时，仅对受影响的 Finding 以证据派生的修订 id 重开复核。这样崩溃证据才真正进入确认门禁，而不会重复复核无关 Finding。

## 后果

- 审计的模型调用成本上升（多轮循环取代单次调用）。由 `AgentLoopBudget` 限制轮次、步数与 token，并在任务资源预算内收敛。
- 「审计」语义从「一次分类」变为「一次有界调查」，报告的证据链现在能显示调查步骤（工具、参数、观察摘要、决策理由）。
- 二进制伪代码进入模型输入，意味着更多受样本影响的文本进入带工具目录的循环。系统提示已声明上下文为不可信数据；调查工具全部只读、禁网、不接受宿主路径。
- 需要同步维护：`vulnweaver_pair.pseudocode_text` 是伪代码形状的唯一所有者，后续任何读取方都必须经它。
- 沙箱内联动态验证（智能体在循环内主动发起符号执行）本次**未实现**，见下。

## 未决

智能体在循环内自主发起动态验证（`symbolic-execute` 经 Sandbox Runner）尚未实现。已就位的部分：`finding-report` 接受 `verification_request` 字段，确认事实推导使动态验证的产物真正能确认 Finding。未就位：内联 Runner 的注入接线、以 PAIR 为准的目标地址校验、以及单次审计的内联动态次数上限。该能力需要先完成上述三项并补真实 Runner 回放，属后续任务。

## 验证

Linux Dev Container 内：`ruff check .` 通过、`pyright` 0 错误、`pytest -q` **496 passed / 5 skipped**（5 项为需 live Sandbox Runner/Docker 的显式 opt-in）。新增测试覆盖：工具注册与只读边界（含遍历路径拒绝与自由文本 rationale 不再误杀）、列表形状伪代码读取回归、智能体「调查→报告→收尾」全链与决策轨迹、幻觉位置丢弃、模型未配置时回落一次性路径、静态线索不自动成为 Finding、崩溃证据确认内存破坏 Finding、模型解释不得贡献事实、崩溃不足以确认注入类、复核修订 id 幂等且与首次复核区分。
