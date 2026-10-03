# 项目文档索引与事实边界

当前实现状态以根目录 [`DEVELOPMENT_STATUS.md`](../../DEVELOPMENT_STATUS.md) 和代码为准。2026-10-03 的主链路代码审查及未修复缺陷见 [`code-review-2026-10-03.md`](code-review-2026-10-03.md)。自动 PoC/Exploit 的成功状态目前不等于目标样本漏洞已复现；确认事实传递、Finding 粒度与大样本覆盖也存在未解决问题。

- 根目录《系统架构设计与技术选型》《系统实现模块拆分》描述目标架构和验收条件，不能替代当前实现验收。
- [`adr/`](adr/) 保存当时接受的技术决策及其历史验证范围；ADR-027、032、034 已补充本次代码复核勘误。其他 ADR 的历史决策未因本次审查整体失效，也不表示所有后果都已通过端到端验证。
- [`progress/`](progress/) 和 [`dev-branch-worklog.md`](dev-branch-worklog.md) 是历史快照，原始时间点的测试数字与完成记录保留；查看现在的阻碍和修复优先级请返回状态台账。
- [`reporting-module-design.md`](reporting-module-design.md) 和 [`binary-analysis-runtime.md`](binary-analysis-runtime.md) 已标注本次发现的上游事实与覆盖限制。各样本、包和应用 README 仅描述各自用途；未涉及审查缺陷的文件不作无事实依据的批量改写。
