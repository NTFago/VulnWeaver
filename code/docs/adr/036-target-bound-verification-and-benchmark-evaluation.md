# ADR-036：目标绑定验证与隔离 benchmark 评测

- 状态：已接受，分阶段实施中（用户于 2026-10-03 确认）
- 日期：2026-10-03
- 相关：ADR-012、025、027、031、032、034、035
- 方案：[面向真实世界 benchmark 的架构改进](../benchmark-oriented-architecture.md)

## 背景

2026-10-03 代码审查发现自动验证未实际执行内层生成脚本、缺目标输入且将工具成功映射为可利用；派生脚本会推进原样本版本，证据传递不完整。补充阅读发现源码 harness 路径编译独立生成程序，缺少原项目构建与链接绑定。继续扩展模型与工具不能建立可审计的真实目标结论。

## 提议

1. 保留既有控制面、数据库/CAS、Registry/Policy 和 Runner；建立不可变 TargetSnapshot、登记构建配方以及可校验的 ExecutionBundle。先以现有单 input_ref 承载 bundle，不引入任意命令、多宿主路径或任意容器参数。
2. 每项实验绑定真实目标构建、驱动、输入和环境；驱动是独立派生工件，不改变原样本当前版本。目标构建和原生执行均经 Runner，原目标必须参与链接或被实际调用。
3. 工具运行状态与漏洞判定分离。登记的独立 Verifier 产生有来源的类型化观测和事实，模型输出标记不能直接确认漏洞；独立复核提供根因审查。候选验证与利用验证保留不同授权门禁。
4. 使用持久 InvestigationCase 记录入口、缺陷精确位置、约束、证据与反例；fuzz 可在候选确认前探索，并独立登记 crash。覆盖与截断显式记录。
5. 隔离 agent 可见数据与 grader 真值，区分已知复现、盲发现和完整补丁 E2E；官方评分与补充证据质量分别报告。

## 不改变的安全约束

Runner 仍是唯一运行时访问者；非 root、只读根、drop capabilities、no-new-privileges、默认禁网不放宽。ADR-025 容器资源策略保持。评测控制面的总时间/模型成本停止条件不等于容器资源配额。SEC-bench Pro 内核轨要求的 privileged/KVM 当前不支持；不得为了评分绕过边界。

## 替代方案与后果

只修复 JSON 执行和 marker 白名单不能解决错误目标或模型自证；重写整个技术栈成本大且没有证据表明框架是首要瓶颈。选择逐阶段替换发现/验证内核，可以复用现有可靠性基础，但需要公共契约、数据库迁移、所有消费者和真实 Runner 正反例联合升级。旧的自动 EXPLOITABLE 记录不得直接迁移为新协议的已验证结论。

该决策已获接受，分阶段实施中。2026-10-03 第一个安全检查点使旧 proof 成功状态返回 `INCONCLUSIVE`、停止将脚本自报 marker 写为强证据，并将生成脚本登记为独立派生工件。同日目标绑定版本通过过一轮真实 Runner 验收；对 `main @ 2757f35` 的后续复核又发现 manifest 成员比较错误和目标/报告器同进程导致的 observation 伪造。修复分支现将每轮目标调用移入独立限时子进程、由父入口独立写报告，并让 worker 与 bundle manifest 交叉核对。全量 Python 门禁为 711 passed / 4 skipped、覆盖率 81.69%；真实 Runner 正反例 3 passed。`target_exception_attributed` 仅表示目标函数中的异常在输入下可重复；PoC 结果为 `INCONCLUSIVE`，observation 仅记录为 `SUPPORTING` evidence，review 不据此推导崩溃、可控输入或匹配环境事实。合并后的最终镜像重建与服务重启仍待验收。P0 的能力边界：目标类为 Python 源码样本；C/C++ 原项目构建绑定（BuildProfile 与完整 TargetSnapshot）、InvestigationCase 与隔离评测在 P1+。后续逐阶段明确 Schema 版本、兼容读取/写入策略和迁移；完整阶段与指标见方案，不设置未经基线测量的成功率承诺。
