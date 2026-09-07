# ADR-007：项目名称与工程标识

- 日期：2026-09-07
- 状态：已接受
- 影响模块：全部模块、镜像、Compose、文档和发布流程

## 上下文

项目需要一个简洁、可辨识，并能表达“智能体分析与证据驱动漏洞确认”的名称。工程标识还需要满足 Python、Node.js、Docker 镜像和 Compose 的命名要求。

## 决策

- 英文名称：`VulnWeaver`
- 中文名称：`漏洞织鉴`
- 工程标识与镜像前缀：`vulnweaver`
- 标语：`Evidence-driven agentic vulnerability discovery`

名称表达系统将静态分析、调用路径、动态验证和复核证据编织为可信漏洞结论。

## 后果

后续 Python 包、Node.js 工作区、Compose 项目、容器、镜像和发布产物统一使用 `vulnweaver` 前缀。改变名称需要同步更新全部构建、部署和文档引用。
