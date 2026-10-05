# ADR-038：审计智能体的沙箱命令执行工具

日期：2026-10-04　状态：已接受

## 背景

审计智能体（`CodeAuditAgent`）目前只有两类调查能力：进程内只读工具（读码、搜索、
调用邻域、facts）和一个窄沙箱工具（`symbolic-execute`，只接受已索引函数地址）。
候选 PoC 链路（ADR-034）执行的是受限调用描述（目标函数 + crafted/control 输入），
模型从不生成可执行脚本。实际审计中这不够：智能体经常需要"跑一下看行为"——
提取样本、用 python 验证解析器行为、跑一条解码链、观察输入差分——只能靠猜。
用户方向明确：让智能体能在沙箱里自己输命令、自己写脚本做 PoC 验证，
而不是被内置工具清单框死。

## 决策

新增一个**注册工具** `agent-sandbox`（版本 1.0.0），由审计智能体以
`sandbox-command` 工具名调用。模型输出一条 shell 命令字符串，经既有全链执行：

```
模型 ActionPlan → Tool Registry / Policy Engine（agent 侧 spec）
→ Sandbox Runner（runner 侧 spec + SandboxCommandProfile）
→ 一次性容器：--network none、--read-only、--cap-drop ALL、
  no-new-privileges、非 root 10001、/work 与 /tmp tmpfs、
  /input 只读挂载、digest 锁定镜像、请求超时 + 容器清理
```

### 信任边界论证

- **红线 2（登记工具）**：命令字符串是一个**已登记 ToolSpec 的结构化参数**，
  command_schema 校验（1..3800 字符、无控制字符），不是未登记的任意工具。
- **红线 3/4（唯一容器入口 / 隔离不放宽）**：执行走 Sandbox Runner 唯一入口，
  容器隔离参数与既有工具完全相同，一个字都没放宽。命令与样本同样属于
  "一次性容器内不可信内容"：容器用完即焚、禁网、无宿主机路径。
- **红线 6（任意命令字符串）**：该红线的对象是**控制面/容器运行时接口**——
  worker 依然不能指定容器参数、宿主路径或未登记镜像；argv 由可信 profile
  构造，模型只能填 `-c` 后面的那一个字符串，而这个字符串的全部破坏力
  被封闭在一次性禁网容器内，与既有 PoC bundle 执行的目标代码同级。
  这是对红线的**合理解释**而非绕过：解释依据是"沙箱内容物即沙箱存在的目的"。
- **红线 7（模型输出不可信）**：命令输出按不可信数据处理，有界回读
  （stdout/stderr 各有上限），不改变系统指令、权限或策略。
- **红线 8（确认链不变）**：本工具的观测**只作诊断证据**（与 angr facts、
  sink 观测同级），不能把 Finding 推向 confirmed；确认仍只走 FindingPolicy
  与既有 verified 链。工具描述与系统提示词都明确声明这一点。
- **红线 10/11（exploit 门槛 / PoC 内容约束）**：exploit 仍只处理 confirmed
  Finding；禁网容器使持久化、横向移动、外联天然不可达。
- **项目级门控**：与 `symbolic-execute` 相同——仅在项目开启动态验证
  （`exploit_validation_enabled`）时可用，每次审计 attempt 次数上限
  （8 次），输入必须锚定到本任务已索引的制品版本，观测有界。

### 有意不包含（留待后续决策）

- **网络访问**：默认禁网不变。`pip install` 类需求走镜像构建（部署期动作），
  不做运行时网络开关；若将来开放，须项目级显式 opt-in + 独立 ADR。
- **多输入 / 任意镜像**：单输入（锚定制品）+ 注册镜像摘要锁定。
- **输出文件回投 CAS**：v1 观测只含 exit code 与有界 stdout/stderr；
  产物回投涉及派生工件登记，留待需要时另议。

### 资源预算

按 ADR-025：容器不设 CPU/内存/磁盘配额，请求超时（取任务
`resource_budget.timeout_seconds`）与容器清理兜底；每次 attempt 的
命令次数上限与审计墙钟 deadline（默认 8h，可配）是仅有的两道执行预算。

## 影响

- `vulnweaver_sandbox_runner_service`：新增 `agent-sandbox` spec + profile
  （复用 proof 镜像，无新镜像；`/bin/sh -c`，工作目录 `/work`）。
- `audit_tools`：新增 `sandbox-command` ToolSpec、执行器分发与门控。
- `analysis-worker`：新增 `_AgentSandboxRunner`（构建 SandboxRequest、
  有界回读观测），接线到 `CodeAuditAgent`。
- 系统提示词补一段使用纪律：样本只读挂载在 /input/input.bin、可写目录
  /work、禁网、输出有界、观测仅诊断。
- 沙箱协议未变（无新镜像、无新端点）；重建 sandbox-runner 与
  analysis-worker 镜像即可部署。
