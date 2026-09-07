# VulnWeaver（漏洞织鉴）

> Evidence-driven agentic vulnerability discovery — 以证据编织可信漏洞结论。

VulnWeaver 是一个面向已授权源码仓库和二进制样本的大模型智能体漏洞挖掘系统。系统编排源码分析、逆向分析、模糊测试、独立复核与受控验证，并通过可追溯证据链输出漏洞结论。

## 当前状态

项目处于 P0 工程初始化阶段。开发规则、架构设计、模块拆分和动态进度分别见：

- `AGENTS.md`
- `系统架构设计与技术选型.md`
- `系统实现模块拆分.md`
- `DEVELOPMENT_STATUS.md`

全部实现位于 `code/`。

## 版本管理

项目明确使用 Git 进行版本管理，根目录仓库是唯一版本历史来源，`main` 为集成基线分支。分支、提交格式、安全限制与 Agent 交接规则见 `AGENTS.md`；当前任务与未提交状态见 `DEVELOPMENT_STATUS.md`。

Agent 负责日常 Git 版本管理，可以自主创建开发分支、暂存和提交当前任务产生的已验证变更。推送、发布标签和受保护分支合并仍需明确授权或既定交付流程支持。

## 开发环境

前置条件：

- Docker Desktop 或 Docker Engine
- Docker Compose
- 支持 Dev Container 的编辑器（可选）

使用 Dev Container 时，在仓库根目录打开项目并选择“Reopen in Container”。容器会启动 PostgreSQL、Redis，并在首次创建时同步 Python 与 Node.js 工作区依赖。

容器内的 Debian、Python 和 Node.js 依赖默认使用国内源；具体地址与 Docker 基础镜像拉取边界见 `code/README.md`。

也可以从宿主机启动基础设施：

```shell
cd code
docker compose -f compose.yaml -f compose.dev.yaml up -d postgres redis
```

验证 Compose 配置：

```shell
cd code
docker compose -f compose.yaml -f compose.dev.yaml config --quiet
```

开发环境只用于编译、普通测试和服务调试。未知样本、Poc 和利用脚本不得直接在开发容器或宿主机执行，必须由后续实现的 Sandbox Runner 在一次性隔离环境中运行。
