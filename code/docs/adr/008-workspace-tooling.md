# ADR-008：工作区依赖管理工具

- 日期：2026-09-07
- 状态：已接受
- 影响模块：Python 工作区、前端工作区、CI 和开发容器

## 上下文

项目同时包含 Python 后端与 TypeScript 前端，需要可复现的依赖解析、锁文件和多包工作区能力。

## 决策

- Python 使用 Python 3.12 与 uv workspace，依赖由 `pyproject.toml` 和 `uv.lock` 管理。
- TypeScript 使用 Node.js 24 与 pnpm workspace，依赖由 `package.json`、`pnpm-workspace.yaml` 和 `pnpm-lock.yaml` 管理。
- Python 包默认使用清华大学 TUNA PyPI 镜像，Node.js 包默认使用 npmmirror；开发镜像内的 Debian 软件包默认使用 TUNA 镜像。
- 开发工具版本在配置或容器构建参数中显式约束。

## 后果

所有 Agent 必须通过 uv 和 pnpm 修改、同步和运行对应生态的依赖与命令，不得同时引入 Poetry、pip-tools、npm 或 yarn 锁文件。国内源地址集中在 `uv.toml`、`.npmrc`、`.env.example` 和开发镜像构建参数中维护。
