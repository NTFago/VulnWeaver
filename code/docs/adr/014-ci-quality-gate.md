# ADR-014：CI 使用 Ruff、Pyright 与 pytest 分层门禁

- 日期：2026-09-07
- 状态：已接受
- 影响模块：全部 Python 包与应用、TypeScript 工作区、Pull Request 流程

## 上下文

项目已经同时包含 Python 领域逻辑、数据库与 Redis 集成代码，以及由公共 Schema 生成的
TypeScript 契约。代码规范、类型正确性和运行行为属于不同缺陷类别，单一工具无法覆盖。

## 决策

1. Ruff 执行代码规则与静态缺陷检查，负责规范一致性和常见低级缺陷；首版不强制 Ruff Formatter，以免引入与生成器无关的大范围格式差异。
2. Pyright 以 Python 3.12、Linux 平台和 strict 模式检查 `apps/` 与 `packages/`；不再使用 Mypy 作为门禁。
3. pytest 执行单元、契约与关键 PostgreSQL/Redis 集成测试；MVP 阶段总体分支覆盖率门槛为 80%，不为追逐行覆盖率编写低价值测试。
4. TypeScript 工作区检查继续独立执行，防止跨语言生成契约漂移或编译回归。
5. GitHub Actions 在 Pull Request 和手工触发时运行，权限仅为读取仓库内容。`main` 依靠分支保护只接受已通过该必需检查的 Pull Request，不在合并后对同一变更再次执行。
6. uv、Python 包、pnpm 与 Node.js 包沿用项目国内源策略；GitHub Actions 与基础服务镜像由运行器基础设施获取。

## 后果

- `pnpm run check` 是里程碑、合并与 CI 的完整质量入口；日常 MVP 迭代可只运行受影响模块的测试、Ruff 和 Pyright。
- 任一 Ruff、Pyright、pytest、覆盖率或 TypeScript 检查失败都会使 CI Job 失败。
- GitHub 仓库仍需把 `Python quality gate` 配置为 `main` 分支必需检查，才能从平台层阻止未通过的合并。
- 如果绕过分支保护直接推送 `main`，将不会自动运行质量门禁；需继续保持禁止直接推送。
- 类型规则切换会暴露与 Mypy 不同的既有问题；这些问题必须修正或以有理由、最小范围的配置记录处理。
