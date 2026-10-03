# 2026-10-03 主链路代码审查与修复清单

> 本文记录代码审查发现的当前实现缺陷，不是修复完成记录。以代码、定向测试和复现为证据；历史 ADR 记录的是设计决策和当时的验证范围，不能替代本清单的当前状态。优先级中的 P0 表示结果可信度或核心链路已被破坏，P1 表示确定的漏报、确认阻断或数据语义错误，P2 表示覆盖透明度问题。

## 范围和验证边界

沿 `Finding → 自动生成 PoC/Exploit → ProofExecutionService → Sandbox Runner → proof entrypoint → Evidence → ReviewFactContext → FindingPolicy`，以及 `PAIR → agent 调查 → Finding 投影` 追踪实际数据流。没有逐文件审计全部代码，也没有进行真实漏洞样本的原生执行、全栈 PoC 端到端验证或大样本吞吐量基准测试。性能项是代码结构推导，具体耗时需要测量。

Linux 开发容器中，`tests/orchestrator/test_poc_fact_derivation.py tests/proof/test_auto_poc.py tests/orchestrator/test_code_audit.py` 共 21 passed；`tests/proof/test_auto_exploit.py tests/orchestrator/test_semantic_audit.py` 共 11 passed。这些测试不能证明自动验证闭环正确：自动 exploit 测试的沙箱直接返回 `SUCCEEDED`，事实推导测试直接构造包含 `markers` 的 `ReviewEvidenceFact`，两者都绕过了真实断点。另以无害脚本验证：把 `raise RuntimeError(123)` 放入生成器同形状 JSON 的 `script` 字段后，以 Python 代码执行整个 JSON，正常返回且内部脚本没有运行；`_safe_replay_facts` 对含 `markers` 的 PoC recipe 返回值不含 `markers`。

## 缺陷

| ID | 优先级 / 状态 | 代码证据与影响 | 修复及验收入口 |
|---|---|---|---|
| CR-01 | P0 / 受阻 | `packages/proof/auto_exploit.py::_register_script` 把 Python 脚本装入 JSON 的 `script` 字段；`apps/proof-tool/vulnweaver-proof-entrypoint` 对整个 JSON 调用 `runpy.run_path`。JSON 中的字符串字段可以作为 Python 字典表达式成功执行，内部脚本完全不运行。`packages/proof/executor.py::_poc_result` 把任何 `SandboxStatus.SUCCEEDED` 映射成 `EXPLOITABLE`，因此空操作也可产生可利用结论。 | 将执行输入与元数据分离；Proof 结果必须由与原样本绑定的可观察断言决定，退出码 0 只代表工具正常完成。用真实 entrypoint、无害脚本和正反例覆盖“脚本确实执行／无漏洞不能判 exploitable”。在修复及回归前，不把自动 PoC/Exploit 的成功状态当成有效漏洞验证。 |
| CR-02 | P0 / 受阻 | `packages/proof/executor.py::ProofExecutionService.run` 只把 `script_ref` 放入 SandboxRequest；`packages/proof/profiles.py::proof_command_profile` 只向入口传脚本、Finding ID、类型和输出目录；生成提示只包含 Finding 摘要。目标样本没有作为运行输入挂载或传递，当前执行无法证明漏洞存在于上传样本。 | 设计并实现经过项目归属、摘要和类型校验的只读目标输入协议；在隔离沙箱内让脚本访问明确绑定的目标；验证日志、证据和结果绑定样本版本与摘要。此变更影响沙箱请求/信任边界，实施前需 ADR 和契约检查。 |
| CR-03 | P1 / 未开始 | `_register_script` 将脚本版本挂到原样本 `artifact_id` 下；`ArtifactRepository.add_version` 随后把原样本的 `current_version_id` 指向 PoC JSON。后续任务可把该 JSON 当作同类型源码或二进制样本选入。 | 将 PoC/Exploit 登记为独立 DERIVED 工件，并保留对样本版本的来源引用；补数据库与任务再提交回归，保证原样本 current version 不变。 |
| CR-04 | P1 / 受阻 | `packages/proof/executor.py::_persist_poc_evidence` 写入 `markers`，`packages/orchestrator/reviews.py::_safe_replay_facts` 的白名单却删除它；`_derived_poc_facts` 因而无法从真实事实包推导注入类必需事实。鉴权类 `FindingPolicy` 还要求 `constraint_analysis`，当前自动推导没有该事实来源。 | 设计受类型约束的可验证 marker 保留和事实映射，明确 `constraint_analysis` 的证据来源；通过数据库真实证据 → 事实包 → re-review → policy 的定向集成测试，不以直接构造事实对象代替。 |
| CR-05 | P1 / 未开始 | `packages/orchestrator/semantic_audit.py::_resolve_location` 将具体行号或地址归一为函数位置；`_project` 用任务、CWE 和函数位置生成 ID。同一函数内的两个同类问题共用 ID，第二个冲突后被计为 `dropped`。 | 为 Finding 保存并校验语句/指令级位置或稳定问题指纹；补同函数同 CWE 双问题回归，并检查既有重复投影的兼容策略。 |
| CR-06 | P1 / 未开始 | `packages/orchestrator/audit_tools.py::_search_source` 按函数循环，却把每次函数迭代当作扫描一个文件；默认文件上限可能被同一文件的多个函数耗尽，后续文件漏搜。`SemanticAuditor._auditable_functions` 全量读取后截取前 256 个，单次回退审计覆盖不完整。`AuditStepExecutor._report` 不检查是否真正读过所报告的代码；“亲读代码”当前只是提示词约束。 | 搜索按唯一 `(version_id, path)` 迭代并报告总范围/未扫描范围；审计采用可继续的分页/候选调度，报告工具校验必要的读取/定位证据；用多函数单文件和同任务多文件测试。 |
| CR-07 | P1 / 未量化 | `SemanticAuditor._auditable_functions` 全量读取函数后 agent `AuditWorkspace.load` 再读一次；`PairRepository.neighborhood` 每次查询加载该版本全部节点、边及函数，再在 Python 中选邻域。数据传输和解码随调查步数、诊断数重复放大。 | 先用代表性大样本记录 SQL 行数、字节量、延迟和内存；把邻域筛选下推数据库、改用索引和按需投影，避免入口双重全量装载；回归功能与性能。具体收益未测，不写成已验证数字。 |
| CR-08 | P2 / 未开始 | `packages/binary-analysis/types.py::BinaryAnalysisAggregate.merge` 达到函数、指令等上限后静默不再追加，没有汇总级截断标记；成功状态不能说明索引完整。 | 记录每类输入数、保留数、截断原因和受影响范围；将覆盖信息传至 agent 与报告。用超限固定样本验证缺口可见。 |

### 代码入口

| 缺陷 | 关键位置 |
|---|---|
| CR-01 | [脚本包装](../packages/proof/src/vulnweaver_proof/auto_exploit.py#L222)、[proof 入口](../apps/proof-tool/vulnweaver-proof-entrypoint#L28)、[成功映射](../packages/proof/src/vulnweaver_proof/executor.py#L463) |
| CR-02 | [沙箱请求](../packages/proof/src/vulnweaver_proof/executor.py#L401)、[命令参数](../packages/proof/src/vulnweaver_proof/profiles.py#L74)、[生成提示](../packages/proof/src/vulnweaver_proof/auto_exploit.py#L270) |
| CR-03 | [脚本版本归属](../packages/proof/src/vulnweaver_proof/auto_exploit.py#L242)、[current version 更新](../packages/persistence/src/vulnweaver_persistence/repositories.py#L334) |
| CR-04 | [marker 写入](../packages/proof/src/vulnweaver_proof/executor.py#L243)、[事实白名单](../packages/orchestrator/src/vulnweaver_orchestrator/reviews.py#L243)、[类别必需事实](../packages/domain/src/vulnweaver_domain/policies.py#L41) |
| CR-05 | [位置归一](../packages/orchestrator/src/vulnweaver_orchestrator/semantic_audit.py#L805)、[ID 与冲突处理](../packages/orchestrator/src/vulnweaver_orchestrator/semantic_audit.py#L583) |
| CR-06 | [源码搜索](../packages/orchestrator/src/vulnweaver_orchestrator/audit_tools.py#L682)、[256 函数截断](../packages/orchestrator/src/vulnweaver_orchestrator/semantic_audit.py#L382)、[报告工具](../packages/orchestrator/src/vulnweaver_orchestrator/audit_tools.py#L923) |
| CR-07 | [重复载入](../packages/orchestrator/src/vulnweaver_orchestrator/audit_tools.py#L346)、[全图邻域](../packages/persistence/src/vulnweaver_persistence/repositories.py#L2162) |
| CR-08 | [默认上限](../packages/binary-analysis/src/vulnweaver_binary_analysis/types.py#L25)、[聚合行为](../packages/binary-analysis/src/vulnweaver_binary_analysis/types.py#L154) |

## 当前使用与交接

上述缺陷尚未修复。过去的 `pytest` 通过、`import/semantic_audit/report` Job 成功或前端性能改善，只证明相应局部链路；不能推出自动 PoC 在真实样本上执行成功、Finding 确认可信或大样本索引完整。处理顺序：CR-01/02 的结果可信度与目标输入、CR-04 的证据闭环、CR-03 的工件语义、CR-05/06 的覆盖与漏报，再对 CR-07/08 测量和优化。修复每个断点后，使用授权的无害教学样本在 Sandbox Runner 内完成真实跨组件正反例验收，并在 `DEVELOPMENT_STATUS.md` 更新状态。
