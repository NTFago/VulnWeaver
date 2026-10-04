# 2026-10-04 分支复审与质量门禁

审查范围：`feat/realworld-acceptance-samples` 相对 `main` 的 proof 观测、复核事实、分页审计、覆盖率配置，以及开发容器内的完整质量门禁。RA-02～RA-05 的修复代码和回归与记录一致；RA-01 在更深的目标代码信任边界上仍有缺口。本轮没有原生运行未知样本；以下 proof 问题由代码路径推导，待经 Sandbox Runner 用固定无害样本补负例。

> 修复记录（2026-10-04，`add7676`）：三项均已处理。RG-01/RG-02 按解除条件的后者执行——`reviews.py` 不再从差分 POC 证据派生任何注入/鉴权确认事实，marker 仅作诊断，注入/鉴权 Finding 保持候选；ADR-036 记录"同进程解释器内无法构造目标不可伪造观测"的结论，可信观测与输入传播判据（crash oracle P0.5 / oracle 提案 §5）另行提案。RG-03 已修复：扫描按完整限定路径解析（镜像运行时语义），同名歧义、条件分支重复定义与别名赋值一律拒绝。Runner 负例已补（`tests/proof/test_target_bound_injection_negatives.py`，opt-in）：exit-20 伪装与常量 sink 固定"伪造可落地、确认不可达"，profiler 致盲固定保守方向；真实 Runner 复跑 6 passed（含原有正反例 3 项）。

## 待修复问题

| 编号 | 优先级 | 证据及影响 | 解除条件 |
|---|---|---|---|
| RG-01 | P0 | `apps/proof-tool/vulnweaver-proof-target-worker` 在目标函数同一进程中设置 `sys.setprofile`，退出码 20 表示 sink 触发；`vulnweaver-proof-entrypoint:324` 仅凭该退出码写 `sink_fired=True`。目标 Python 代码可调用 `os._exit(20)`，绕过 worker 的 `finally` 和报告逻辑，并在退出前 `print(..., flush=True)` 形成与 control 不同且重放稳定的输出；父进程会把它当成完成并触发 sink。目标也可通过 `sys.setprofile(None)` 造成漏报。故“解释器事件不可伪造”不能推出“退出码不可伪造”。 | 将 sink 观测移出目标可控制的解释器/退出状态，或在可信观测到位前禁止 `sink_reached` 派生强证据。补真实 Runner 正反例，含退出码伪装和关闭 profiler。涉及证据确认边界，实施时更新 ADR-036。 |
| RG-02 | P0 | `proof/verifier.py::differential_evidence_from_observation` 把任意被探针看见的词典 C 调用写为 `sink_reached`；`orchestrator/reviews.py::_derived_poc_facts` 直接升级为 `source_to_sink_path`。路径中没有校验 crafted 输入到该调用参数的数据流。例如目标函数先执行常量 `eval("1+1")`，再返回输入，control/crafted 输出稳定不同，三次调用都触发 sink，但输入没有进入 sink。 | 以动态参数传播/污点证据或等价可执行判据证明输入到具体 sink，并将 sink 身份与 Finding 位置绑定；未满足时只记录诊断，不授予 `source_to_sink_path`。 |
| RG-03 | P1 | `proof/protection_analysis.py::scan_target_protections` 用函数短名建立 AST 字典，再用 `target_callable.split(".")[-1]` 选择节点。两个类各有同名方法时，后一个节点会覆盖前一个；对第一个类方法的执行却可能枚举第二个类方法的保护构造。扫描还总添加 `callable_resolved`，使 `reviews.py::_derived_poc_facts` 的非空列表条件无法识别这种错位。 | 按完整限定名和代码位置解析绑定 callable，校验扫描节点与执行目标一致；补同名方法、嵌套函数及错误位置负例。 |

## 质量门禁改动

- 原 `pnpm run check` 串行执行，且没有 contracts 生成漂移检查和 Web 生产构建。现统一并行启动 Ruff、Pyright、pytest、contracts、TypeScript/Web 检查，完整输出逐行标注来源，所有检查完成后按任一失败返回非零；每项列出耗时。
- 统一入口将工作区 `apps/*/src`、`packages/*/src` 放到 `PYTHONPATH` 前端，避免 Linux 开发容器复用旧 wheel 测到过时代码。各项独立脚本仍可直接调用；跨分支更新依赖时仍需按 `DEVELOPMENT_STATUS.md` 的 Q-003 同步环境。
- pytest 保留四 worker 和完整 `term-missing` 报告，追加最慢 20 项耗时用于定位热区。覆盖率纳入先前遗漏的 `proof`、`reporting`，排除自动生成的声明文件，避免总阈值被生成代码抬高。

验证数字与剩余风险见根目录 `DEVELOPMENT_STATUS.md`。本轮质量门禁变更没有修改产品确认路径，RG-01～03 仍阻止将注入 Finding 的现有证据链视为可信闭环。
