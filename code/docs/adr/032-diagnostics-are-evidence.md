# ADR-032：扫描器诊断证据化——工具结果不再是候选 Finding

- 状态：已接受
- 日期：2026-09-28
- 相关：ADR-027（智能体驱动审计）、ADR-030（调查记忆）、ADR-031（智能体引导投放）

## 背景

"不要太依赖工具的结果"的最后一处结构性残留：`StaticFindingProjector` 把静态扫描器的 diagnostics 直接落库为 `CANDIDATE` Finding——**工具输出未经任何智能体判断就取得了与 agent 亲读代码产出的候选同等的身份**，并由此进入评审、报告与工作台。ADR-027 已把扫描器输出在审计循环内降级为"线索"，但落库层仍是"工具→Finding"。

拆解的障碍：`static-leads` 调查工具恰恰从这些 Finding 行读取线索（经由 FindingEvidence 关联找 TOOL_OUTPUT 证据）——线索的存储寄生在要拆除的结构上。

## 决策

### 1. 诊断只落证据，不再落 Finding

`StaticFindingProjector` 只创建 TOOL_OUTPUT 证据（携带 PAIR 快照与 `diagnostic_selector`：tool/rule/cwe/severity/message/location），不再 `upsert_candidate`、不再建立 FindingEvidence 关联。`StaticFindingProjection` 收窄为仅 `evidence_ids`（executor 只消费它）。**一个 diagnostic 成为 Finding 的唯一路径：审计智能体读了代码后用 `finding-report` 重新报告并锚定。**

`replay_recipe.diagnostic_selector` 补充 `severity` 与 `message`——线索的全部内容从此自足于证据行。

### 2. static-leads 改从证据层读取

`AuditWorkspace.static_leads` 遍历任务工件版本的 `object_ref`（证据的 `input_ref` 即上传工件引用），过滤 `kind == "static_analysis_diagnostic"` 的 TOOL_OUTPUT 证据，投影为线索条目（cwe/scanner/rule/severity/message/位置）。旧形状里的 `finding_id`/`status` 不复存在——它们本就是"工具结果顶着 Finding 身份"的痕迹。selector 缺字段的旧证据行降级展示，不报错。

### 3. 语义后果

- 评审只评审 agent 报告的候选：扫描器的每个命中必须经智能体读代码确认后才会出现在评审与报告里——"工具只是参考，智能体是主力"在数据模型层面成立。
- 审计失败的降级路径本就不放行评审产出（审计失败 → 任务失败），删除扫描器 Finding 不产生新的 NO_FINDINGS 风险。
- 多扫描器命中同一位置的合并语义消失（每条 diagnostic 独立成证据）——合并是判断行为，归 agent。

## 验证

dev container（栈内 PostgreSQL 实跑）：`tests/orchestrator` + `tests/binary_analysis` + `tests/source_analysis` **206 passed / 1 skipped**；ruff 通过；pyright 0 errors。关键断言更新：static lineage 测试验证「诊断仅产生证据、零 Finding 行」；leads 测试以真实上传版本 object_ref 作 input_ref 播种，验证线索从证据层浮现（cwe/scanner/rule/path）。
