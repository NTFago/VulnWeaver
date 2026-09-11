# VulnWeaver 中文审计报告

## 1. 执行摘要

| 项目 | 内容 |
| --- | --- |
| 被测样本 | calculator.zip（内容摘要 sha256:1ab2bdc6cdea4e959c7b0ce3259d48b60c0b09ec8b3a070a600ccadcf213aea6，类型 源码压缩包） |
| 任务编号 | task:b6d0bce331bc4596abc985e37e2b16c7 |
| 任务结论 | 未提供 |
| 发现漏洞总数 | 3（最高严重等级：严重（critical）） |
| 确认状态 | 不可验证（unverifiable）3 个 |
| 总体风险结论 | 总体风险等级评估为严重（依据最高严重等级 严重）。存在高等级问题，建议立即安排人工复核并优先处置。 |

### 主要限制

- 本次扫描未记录到阶段失败、降级或验证受阻事件。

## 2. 风险统计

### 2.1 严重等级分布

| 严重等级 | 数量 |
| --- | --- |
| 严重（critical） | 1 |
| 高危（high） | 2 |
| 中危（medium） | 0 |
| 低危（low） | 0 |
| 提示（info） | 0 |

### 2.2 确认状态分布

| 状态 | 数量 |
| --- | --- |
| 已确认（confirmed） | 0 |
| 候选（candidate） | 0 |
| 误报（false_positive） | 0 |
| 争议（disputed） | 0 |
| 不可验证（unverifiable） | 3 |

## 3. 漏洞列表

### 3.1【严重 · 注入】Arbitrary code execution via eval() on user-controlled expression（CWE-95）

> 【推测性内容】本节缺少强证据支持，结论可能不成立，需人工复核后方可采信。

| 项目 | 内容 |
| --- | --- |
| 漏洞编号 | finding:be1b639b6898c26e47ee735e0fbdf15b |
| 严重等级 | 严重（critical） |
| 可信度 | 0.40（中等可信（待验证）） |
| 状态 | 不可验证（unverifiable） |
| 类别 | 注入（injection） |
| 受影响位置 | calculator.py:17-19（源码位置） |

#### 触发条件与调用路径

- 漏洞目标函数 evaluate（calculator.py:17）
- 调用方 main（calculator.py:22）

#### 证据链明细

- 证据引用：evidence:5cf078d4cda5f0b716951b0dca3d6735, evidence:review:5811293110124b04f78b89c38bdc03149d3ae71a7dbe9d1e33b603c48669052c
- 复核引用：review:5811293110124b04f78b89c38bdc03149d3ae71a7dbe9d1e33b603c48669052c
- evidence:5cf078d4cda5f0b716951b0dca3d6735：模型推断说明（model_explanation），背景信息，来源工具 vulnweaver-semantic-audit@1.0.0，工件引用 cas://sha256/fe5f8138a691bdabbea443fb7b113b3d2dc3d9504fee71d8b63c1c8808adfac2（内容摘要 sha256:fe5f8138a691bdabbea443fb7b113b3d2dc3d9504fee71d8b63c1c8808adfac2）
- evidence:review:5811293110124b04f78b89c38bdc03149d3ae71a7dbe9d1e33b603c48669052c：复核结论（review_conclusion），背景信息，来源工具 未提供，工件引用 cas://sha256/212bd4cfd17e09700d72dd83acd3060576cf92fe3d7a1d852719a8e65ee2e358（内容摘要 sha256:212bd4cfd17e09700d72dd83acd3060576cf92fe3d7a1d852719a8e65ee2e358）

#### 影响分析

该问题属于注入类缺陷：外部可控数据未经充分校验即进入敏感执行环节，可能造成命令注入、代码注入或查询注入。当前评估等级为严重，可信度 0.40（中等可信（待验证））。

#### 修复建议

Address the audited pattern associated with CWE-95.

#### 验证状态

- 未执行动态验证：该发现没有关联的 Poc 执行记录。

#### 待人工确认项

- 当前状态为不可验证（unverifiable），尚未确认为真实漏洞。
- 现有证据中不含强证据，结论强度有限。

### 3.2【高危 · 注入】Static analysis candidate for CWE-95（CWE-95）

> 【推测性内容】本节缺少强证据支持，结论可能不成立，需人工复核后方可采信。

| 项目 | 内容 |
| --- | --- |
| 漏洞编号 | finding:d5db87f48718e4ae553826da7b5180a8 |
| 严重等级 | 高危（high） |
| 可信度 | 0.60（较可信） |
| 状态 | 不可验证（unverifiable） |
| 类别 | 注入（injection） |
| 受影响位置 | calculator.py:19（源码位置） |

#### 触发条件与调用路径

- 漏洞目标函数 evaluate（calculator.py:17）
- 调用方 main（calculator.py:22）

#### 证据链明细

- 证据引用：evidence:ed1fb8fce0f1aa84cc138a7f8ae5501f, evidence:review:c827651e28333e4f92c4f488c73db9d3811930e05010bdf63e5b9dd92d2de304
- 复核引用：review:c827651e28333e4f92c4f488c73db9d3811930e05010bdf63e5b9dd92d2de304
- evidence:ed1fb8fce0f1aa84cc138a7f8ae5501f：工具输出（tool_output），支持性证据，来源工具 semgrep@1.0.0，工件引用 cas://sha256/3d829b6e772527bc382a889d3c37f76718c2ecc14649901b61df645c74e1a0f9（内容摘要 sha256:3d829b6e772527bc382a889d3c37f76718c2ecc14649901b61df645c74e1a0f9）
- evidence:ed1fb8fce0f1aa84cc138a7f8ae5501f 工具退出码：0
- evidence:review:c827651e28333e4f92c4f488c73db9d3811930e05010bdf63e5b9dd92d2de304：复核结论（review_conclusion），背景信息，来源工具 未提供，工件引用 cas://sha256/cae2b26001300ac32d769cfb4a3b31a2351df132d14e0f7bc56d6f295f60ff5a（内容摘要 sha256:cae2b26001300ac32d769cfb4a3b31a2351df132d14e0f7bc56d6f295f60ff5a）

#### 影响分析

该问题属于注入类缺陷：外部可控数据未经充分校验即进入敏感执行环节，可能造成命令注入、代码注入或查询注入。当前评估等级为高危，可信度 0.60（较可信）。

#### 修复建议

Review and remediate the code pattern associated with CWE-95.

#### 验证状态

- 未执行动态验证：该发现没有关联的 Poc 执行记录。

#### 待人工确认项

- 当前状态为不可验证（unverifiable），尚未确认为真实漏洞。
- 现有证据中不含强证据，结论强度有限。

### 3.3【高危 · 注入】Untrusted command-line argument forwarded to eval() sink in main()（CWE-95）

> 【推测性内容】本节缺少强证据支持，结论可能不成立，需人工复核后方可采信。

| 项目 | 内容 |
| --- | --- |
| 漏洞编号 | finding:b53fe6d09fea34b81b6ad4e4a952b386 |
| 严重等级 | 高危（high） |
| 可信度 | 0.40（中等可信（待验证）） |
| 状态 | 不可验证（unverifiable） |
| 类别 | 注入（injection） |
| 受影响位置 | calculator.py:22-32（源码位置） |

#### 触发条件与调用路径

- 漏洞目标函数 main（calculator.py:22）
- 被调用方 evaluate（calculator.py:17）

#### 证据链明细

- 证据引用：evidence:df68d1890579f5dc6d31dee927fd2f87, evidence:review:0f7c6b5be04ca6af642053f113032b84b0a1e5d1c775144d9f9ff869d5efd0a2
- 复核引用：review:0f7c6b5be04ca6af642053f113032b84b0a1e5d1c775144d9f9ff869d5efd0a2
- evidence:df68d1890579f5dc6d31dee927fd2f87：模型推断说明（model_explanation），背景信息，来源工具 vulnweaver-semantic-audit@1.0.0，工件引用 cas://sha256/fe5f8138a691bdabbea443fb7b113b3d2dc3d9504fee71d8b63c1c8808adfac2（内容摘要 sha256:fe5f8138a691bdabbea443fb7b113b3d2dc3d9504fee71d8b63c1c8808adfac2）
- evidence:review:0f7c6b5be04ca6af642053f113032b84b0a1e5d1c775144d9f9ff869d5efd0a2：复核结论（review_conclusion），背景信息，来源工具 未提供，工件引用 cas://sha256/8e8487540379981644605dffd1bb67d300d64346afe2d0ca7e650391173dd95c（内容摘要 sha256:8e8487540379981644605dffd1bb67d300d64346afe2d0ca7e650391173dd95c）

#### 影响分析

该问题属于注入类缺陷：外部可控数据未经充分校验即进入敏感执行环节，可能造成命令注入、代码注入或查询注入。当前评估等级为高危，可信度 0.40（中等可信（待验证））。

#### 修复建议

Address the audited pattern associated with CWE-95.

#### 验证状态

- 未执行动态验证：该发现没有关联的 Poc 执行记录。

#### 待人工确认项

- 当前状态为不可验证（unverifiable），尚未确认为真实漏洞。
- 现有证据中不含强证据，结论强度有限。

## 4. 附录

### 4.1 任务元数据

| 项目 | 内容 |
| --- | --- |
| 任务编号 | task:b6d0bce331bc4596abc985e37e2b16c7 |
| 创建时间 | 2026-09-11T03:41:43.086731Z |
| 最后更新 | 2026-09-11T03:46:45.964320Z |
| 报告工具 | vulnweaver-report@1.0.0 |

### 4.2 失败原因汇总

- 本次任务没有失败记录。

### 4.3 复核历史

- finding:be1b639b6898c26e47ee735e0fbdf15b：review:5811293110124b04f78b89c38bdc03149d3ae71a7dbe9d1e33b603c48669052c 结论 不可验证（unverifiable）；复核模型 review-model/deepseek-flash；理由 Confirmation policy denied: missing_fact:minimal_reproduction, missing_fact:protection_analysis, missing_fact:source_to_sink_path, missing_strong_reproducible_evidence；时间 2026-09-11T03:42:15.852839Z
- finding:d5db87f48718e4ae553826da7b5180a8：review:c827651e28333e4f92c4f488c73db9d3811930e05010bdf63e5b9dd92d2de304 结论 不可验证（unverifiable）；复核模型 review-model/deepseek-flash；理由 Confirmation policy denied: missing_fact:minimal_reproduction, missing_fact:protection_analysis, missing_fact:source_to_sink_path, missing_strong_reproducible_evidence；时间 2026-09-11T03:42:02.815963Z
- finding:b53fe6d09fea34b81b6ad4e4a952b386：review:0f7c6b5be04ca6af642053f113032b84b0a1e5d1c775144d9f9ff869d5efd0a2 结论 不可验证（unverifiable）；复核模型 review-model/deepseek-flash；理由 Confirmation policy denied: missing_fact:minimal_reproduction, missing_fact:protection_analysis, missing_fact:source_to_sink_path, missing_strong_reproducible_evidence；时间 2026-09-11T03:42:09.261017Z

### 4.4 数据说明

- 原始工具输出与运行日志以不可变工件引用保存，本报告仅嵌入引用，不复制原始内容。
- 全部结论均可追溯到扫描结果字段；字段缺失时显示「未提供」。
