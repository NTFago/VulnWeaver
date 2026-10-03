# 2026-10-03 主链路代码审查与修复清单

> 本文记录代码审查发现的当前实现缺陷，不是修复完成记录。以代码、定向测试和复现为证据；历史 ADR 记录的是设计决策和当时的验证范围，不能替代本清单的当前状态。优先级中的 P0 表示结果可信度或核心链路已被破坏，P1 表示确定的漏报、确认阻断或数据语义错误，P2 表示覆盖透明度问题。

> 后续进展（2026-10-04）：下表和 04d1281 章节保留各轮复审时的历史代码证据。针对 `main @ 2757f35` 的复核项已在 `main @ f5bc37e` 修复并部署：全量 Python 门禁 711 passed / 4 skipped、覆盖率 81.69%；重启后的真实 Runner 正反例 3 passed。目标异常映射为 `INCONCLUSIVE`，只产生 `SUPPORTING` observation，FindingReviewGate 不从中推导崩溃事实。受影响镜像已重建、API ready、Web 返回 200。旧自动验证结论不得按新协议追认。
>
> 第二轮修复（2026-10-04，本分支）：CR-04 剩余、CR-05、CR-06、CR-07、CR-08 已实现。CR-08：聚合 merge 逐集合记录 offered/retained/limit/截断原因（契约新增 `BinaryCoverage`），经 result 文档传入规划 facts 与 agent `artifact_facts`/`analysis_baseline`。CR-06：回退审计改为按页（64 函数/页）调用模型并逐页投影+checkpoint 续跑，deadline 兜底（ADR-027 口径 8h），消除 256 函数截断；读取证明键改为 `(version_id, path, line)`，跨版本同路径不再互相授权。CR-05：补二进制同函数双地址回归。CR-07：`PairRepository.neighborhood` 下推为递归 CTE（基准 2000 函数图 402ms→54ms，6000 函数 110ms），审计入口用 `has_functions` 廉价探针，agent 成功路径不再双重全量装载。CR-04 剩余：entrypoint 逐轮捕获有界输出并摘要，新增 `verified_behavior` 判定（crafted≠control 且重放一致）；worker 依据自校验 observation 派生 STRONG `POC_VERIFICATION_RESULT` 标记（注入：sink_reached；鉴权：behavior_difference+constraint_digest 绑定审核期登记约束的 SHA-256），gate 侧白名单恢复 markers 并将约束绑定映射为 `constraint_analysis`。定向验证见 `tests/proof/test_differential_verification.py`、`tests/proof/test_entrypoint.py`、`tests/orchestrator/test_semantic_audit_paging.py`、`tests/binary_analysis/test_coverage.py`、`tests/persistence/test_pair_neighborhood.py`。
>
> 第三轮收尾（2026-10-04，`708a4f4`）：CR-04 全部完成。注入类 `protection_analysis` 独立判据落地：`vulnweaver_proof.protection_analysis` 是控制面确定性 AST 枚举器，对 bundle 摘要锁定的目标源码（经 `load_execution_bundle_member` 读回，非重取副本）解析绑定 callable 及其模块内闭包，枚举危险 sink、异常守卫、输入校验、净化器与安全替代；扫描不可解析或 callable 不可解析时返回 None、证据不带保护 marker——枚举从不发明事实。marker 进入注入类 STRONG 证据后，gate 将 `sink_reached`+`protections_observed` 映射为 `source_to_sink_path`+`protection_analysis`，注入 Finding 全链确认回归通过（`tests/orchestrator/test_confirmation_facts.py::test_injection_with_protection_enumeration_confirms`）。独立崩溃/利用 oracle 完成立项评估（[`oracle-proposal-2026-10-04.md`](oracle-proposal-2026-10-04.md)）：建议 P0.5 采纳 supervisor 计算的解释器信号 `crash_kind`，sanitizer 轨挂靠 P1 BuildProfile，模型声明影响断言因红线 8 否决。全量门禁 742 passed / 4 skipped；镜像重建、栈重启、真实 Runner 验收 3 passed。CR-01~CR-11 及两轮复核项至此全部关闭。

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

初始缺陷的当前状态见 `DEVELOPMENT_STATUS.md`。过去的 `pytest` 通过、`import/semantic_audit/report` Job 成功或前端性能改善，只证明相应局部链路；不能推出自动 PoC 在真实样本上执行成功、Finding 确认可信或大样本索引完整。修复每个断点后，使用授权的无害教学样本在 Sandbox Runner 内完成真实跨组件正反例验收，并在 `DEVELOPMENT_STATUS.md` 更新状态。

## 2026-10-03 合并后复审：目标绑定仍有三个可信度缺口

以下发现来自当前 `main`（`04d1281`）的静态数据流审查，尚未运行新负例的真实 Runner 复现。复审覆盖 proof bundle 组装、入口执行、worker 结果采信、手动 proof API、证据到 review 的传递；没有逐文件审计整个仓库。

| ID | 优先级 / 状态 | 当前代码证据与可达影响 | 修复及验收入口 |
|---|---|---|---|
| CR-09 | P0 / 已修复并验收 | 04d1281 的历史实现以 stderr 推断目标参与。后续曾改成同进程 compile/exec，导致新的报告伪造路径；当前修复每次 invocation 使用目标子进程，supervisor 独立生成报告。 | 入口与真实 Runner 测试确认目标 monkeypatch `json.dumps` 不能伪造报告；真实 Runner 正反例 3 passed。 |
| CR-10 | P0 / 已修复 | 当前入口直接从逐成员摘要校验的 bundle 读取原始目标字节，并在独立子进程调用目标，不再依赖模型可写文件或 stderr 归因。 | `test_entrypoint.py` 与真实 Runner 覆盖目标摘要、报告隔离和正负例。 |
| CR-11 | P0 / 已修复 | bundle 绑定 Finding ID 与 TargetBinding；入口校验成员摘要，worker 根据请求 Finding 的当前 artifact/version/kind/digest 和 bundle manifest 核对 observation，review 再检查 evidence 绑定。 | proof/orchestrator 定向与全量测试通过；真实 Runner 正例和报告伪造负例通过。 |

上述三项修复前，新协议的 `verified_trigger` 不足以独立证明当前 Finding 的原目标被触发。既有正反例测试仍证明它覆盖了当时列出的输入；不能覆盖这三类构造。修复涉及 proof 信任边界，应按 ADR-036 更新契约、调用方及真实 Runner 验收。

## CR-09–11 修复回访（2026-10-03）

- **CR-09**：`ExploitScript` 改为 `ProofInvocation`（目标函数路径 + 输入编码），proof 入口不再执行模型给出的 Python。每次 invocation 由新子进程编译和调用目标，父入口只根据子进程退出状态写观测报告。
- **CR-10**：原目标字节经 bundle 摘要校验后传入子进程；子进程不持有父入口的报告状态。每轮设 30 秒超时，超时后 supervisor 杀掉该进程组。
- **CR-11**：ExecutionBundle 增加 `finding_id`；组装时要求 target member digest 与 TargetBinding digest 相等；入口核对 Finding ID；worker 与复核事实构造都核对 Finding 的 artifact/version/kind/digest。
- **worker 验证**：依据 worker 自建 bundle 校验 driver/inputs/controls 摘要、角色与计数、verdict/reasons 自洽；目标异常 observation 只建立 SUPPORTING evidence，不单独证明漏洞影响。
- **CR-05**：semantic 与 agentic finding-report 均要求提供 `constraint`；同一任务的 CWE+精确位置用于稳定 Finding ID，避免约束措辞变化制造重复候选。
- **重试幂等**：生成的 driver/inputs 从派生工件复用，bundle 时间戳取稳定 Job 创建时间；PoC 和 evidence 同事务写入，timeout/environment 失败遵循 Job retry policy。

验证边界：Linux dev 容器 `pnpm run check:python` 为 711 passed / 4 skipped，覆盖率 81.69%；Ruff、Pyright、contracts `--check` 通过。4 项跳过包括 3 项需配置的真实 Runner 测试和 1 项 Docker runtime integration；真实 Runner 定向重跑为 3 passed。合并后的镜像重建与服务重启仍待验收。

## 2026-10-03 复核 `main @ 2757f35`：入口与观测报告的新缺陷

用户提交的复核报告确认 CR-09/10/11 的目标绑定锚定方向成立、未发现绕过，同时实证两个新的 P0。当前分支已修复：

| ID | 发现 | 修复与验证 |
|---|---|---|
| P0-1 | 成员等值比较没有把必需的 manifest 计入声明集合，导致所有合法 bundle 被拒。 | 比较集合改为 `declared ∪ {MANIFEST_NAME}`；仍保持严格等值；额外成员、符号链接和摘要负例保留。 |
| P0-2 | 目标代码在入口进程内执行，可 monkeypatch 报告器全局并伪造 `verified_trigger`。 | 目标调用移入每轮独立子进程；单轮 30 秒超时并杀进程组；报告只由未执行 bundle 代码的父入口写出。入口和真实 Runner 的 monkeypatch 负例通过。 |
| P1-1 | callable 解析可选择导入模块属性，可能把观测器变成命令执行器。 | 契约拒绝 `__` 路径段，worker 仅接受编译目标模块中的 Python 函数；`os.system` 负例确认 marker 未创建。 |
| P1-2 | worker 未将观测报告的成员摘要、运行次数和 verdict 与自建 bundle 核对。 | 读取并验证 CAS bundle manifest，比较成员摘要/运行角色/计数和 verdict 自洽性；不一致报告不产生 STRONG 证据。 |
| P1-3 | lease 重试时 POC/evidence 冲突可逃逸，部分落库且 retryable 标记阻断重试。 | 生成物复用、时间戳稳定、PoC+evidence 原子事务、超时/环境错误结构化可重试；增加全链重投和 timeout 回归。 |
| P1-5 | agentic `finding-report` 没有 constraint 字段。 | schema、checkpoint serialization、提示词和测试同步；历史 checkpoint 缺字段时用 rationale 暂时兼容。 |
| P1-6 | 任意目标函数异常在对照干净且重放稳定时可成为 `verified_trigger`。 | `verified_trigger` 仅保留为可重复目标异常观测；PoC 结果映射为 `INCONCLUSIVE`，evidence strength 为 `SUPPORTING`，复核不从该 observation 推导崩溃/可控输入/匹配环境事实。正例和复核拒绝确认回归通过。 |

旧 `tests/proof/test_http_replay.py` 使用已废弃的裸脚本协议且不能验证当前 bundle 行为，已删除；目标绑定 HTTP 正反例以 `tests/proof/test_target_bound_runner.py` 为准。full Python 门禁 711 passed / 4 skipped；真实 Runner 定向验收 3 passed。
