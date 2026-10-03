# VulnWeaver（漏洞织鉴）

> Evidence-driven agentic vulnerability discovery — 以证据编织可信漏洞结论。

VulnWeaver 是一个面向已授权源码仓库和二进制样本的大模型智能体漏洞挖掘系统。系统目标是编排源码分析、逆向分析、模糊测试、独立复核与受控验证，并通过可追溯证据链输出漏洞结论。当前实现的自动 PoC/Exploit 链路存在影响结果可信度的阻断缺陷，不能将其成功状态视为漏洞已复现或可利用；代码证据与修复清单见 [`code/docs/code-review-2026-10-03.md`](code/docs/code-review-2026-10-03.md)。

## 当前状态

项目已超出工程初始化阶段；已有导入、审计、报告和部分动态分析实现，但自动验证、确认事实和大样本覆盖尚未完成可信验收。开发规则、设计、模块拆分和动态进度分别见：

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

开发环境只用于编译、普通测试和服务调试。未知样本、PoC 和利用脚本不得直接在开发容器或宿主机执行；任何原生运行样本的行为只能经 Sandbox Runner 在一次性隔离环境中进行。

## 测试用例

演示与分析用的测试样本位于 `code/tests/fixtures/`，包括：

- **加壳闭源样本**（UPX 加壳 ELF）：`packed-overflow-note`（CWE-120）、`packed-command-injection`（CWE-78）
- **混淆闭源样本**（控制流平坦化等）：`obfuscated-heap-overflow`（CWE-122）、`obfuscated-format-string`（CWE-134）
- **源码样本**：`py-eval-calculator`（CWE-95）、`py-cmd-backup`（CWE-78）
- **无害对照**：`benign-checksum`（用于 NO_FINDINGS 路径）

全部为自编无害教学样本（登记来源与授权依据），目录内含构建脚本 `build.sh`（Docker 内幂等构建）、分发二进制 `dist/`（含 SHA-256）与逐样本说明 `README.md`。样例总索引见 `code/tests/fixtures/README.md`。
