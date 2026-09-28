# DEVELOPMENT STATUS

> 轻量交接台账。稳定规则与安全红线见 `AGENTS.md`；历史课设阶段的任务明细见 Git 历史、PR 与 `code/docs/progress/`。

更新时间：2026-09-28（Asia/Shanghai）

## 当前焦点

系统定位已从课设验证升级为**面向真实世界样本的长线漏洞挖掘智能体系统**（见 `AGENTS.md` 与 ADR-028）。当前主线：补齐真实样本分析的第一道门槛——通用脱壳/重建工具链。

**部署栈已被用户清空（容器与镜像全部删除）**，本分支的工作不依赖运行中的栈；重建步骤见「下一步」。

## 进行中

| 事项 | 负责人 / 分支 | 状态 |
|---|---|---|
| T46 分层脱壳工具链（UPX/de4dotEx/unipacker/XOR 恢复/LIEF 重建 + `binary-unpack` 沙箱工具） | ZCode / `feat/unpacking-toolchain` | 待验证：镜像端到端 |

T46 已完成边界（全部位于 `code/`，ADR-028 记录决策）：

- `packages/binary-analysis/src/vulnweaver_binary_analysis/unpacking.py`：`UnpackerChain` 多轮策略链（候选须通过严格解析验收，锚定原始摘要防回吐；多层壳逐层剥离，上限 4 轮）+ 四个解壳器 + `LiefRebuilder`（dump 后 PE 头再序列化修复）+ `BinaryUnpackSandboxAdapter`（worker 侧驱动容器内全链）。
- `executor.py`：本地链（UPX + XOR 恢复）失败且样本仍加壳时，经沙箱 `binary-unpack` 兜底；派生工件按方法登记（`upx-unpacked-binary` 保持不变，新增 `dotnet-cleaned-assembly` / `emulated-unpacked-binary` / `xor-recovered-binary`）。
- `profiles.py` + `apps/binary-tools/vulnweaver-binary-entrypoint` + sandbox-runner 服务：新增 `binary-unpack` ToolSpec/命令 profile（与 `binary-facts` 共用 binary-tools 镜像），入口脚本支持 `--mode unpack`。
- `headers.py`：PE 解析 CLR 数据目录（index 14），`BinaryMetadata.dotnet` 分发 de4dot。
- 镜像：binary-tools 增加 mono-complete + de4dotEx 3.10.0（net48，官方 release）+ `--extra unpack`（unipacker 1.0.8、lief 0.17.6）。

剩余：真实镜像端到端（见「下一步」）。

## 已确认决策（摘要）

- 动态执行（Fuzz/Proof/Exploit）只经 Sandbox Runner；默认禁网、非 root、只读输入。
- 控制面/执行面分离；普通 Worker 不挂 Docker Socket。
- 原始工件不可变；派生工件带摘要、父工件与生成配置。
- ADR-021：先必跑审计基线，再 Finding 驱动复核与深审。
- ADR-025：`resource_budget` 惰性簿记；沙箱不设计算配额。
- ADR-027：审计循环不设规划轮次上限，墙钟 deadline 兜底。
- **ADR-028（2026-09-28）**：分层静态脱壳工具链；unipacker 的 Unicorn 模拟与 angr 同属翻译式处理，原生执行边界不变；重工具只进 binary-tools 镜像。

## 经验教训（仍有效）

- Q-003：Windows 中文路径不用 editable 安装；改动 `packages/` 后容器内需 `uv sync --reinstall-package <pkg>`，否则**静默用旧代码**。
- Q-023：Windows 上新建脚本注意 CRLF（容器 shebang 会断）；本轮已将入口脚本规范化为 LF。

## 最近验证

| 日期 | 验证 | 结果 |
|---|---|---|
| 2026-09-28 | T46 定向测试（Linux 容器 python:3.12-slim + uv 0.10，`uv sync --all-packages --no-editable --group dev`） | `tests/binary_analysis` **54 passed / 3 skipped**（跳过项为 PostgreSQL opt-in，与基线一致）；`tests/sandbox_runner` + `tests/contracts` + `tests/tool_runtime` **44 passed / 1 skipped**（Docker runtime opt-in）；`ruff check .` 通过；`uv lock` 纳入 lief 0.17.6 / unipacker 1.0.8 / unicorn-unipacker 1.0.3b7 |
| 2026-09-28 | pyright | 见本分支提交记录（后台执行中，若未通过将在提交信息中注明） |
| 2026-09-11 | T45/T45-A~F 全量门禁 | `pytest` 556 passed / 5 skipped；ruff、pyright 0 错误；部署栈 UPX 加壳样本端到端通过（历史基线，栈现已清空） |

## 下一步

1. **重建镜像与部署栈**（用户已授权自行重构）：`docker compose build binary-tools analysis-worker sandbox-runner …` → 起栈。binary-tools 构建含 mono/de4dotEx/Ghidra/DIE 下载，需网络可用；构建后先验证 `vulnweaver-binary-entrypoint --mode unpack` 在容器内可执行（shebang/LF/mono 路径）。
2. **真实壳样本端到端**：投递一个 UPX 样本回归既有链路；再投递自制 XOR 壳 ELF（`tests/binary_analysis/samples.py` 的构造方式）验证 `xor-recovered-binary` 派生与后续分析切换；有条件时补 MPRESS/ConfuserEx 样本验证 unipacker/de4dot 路径。
3. pyright 若有新增错误，修复后再合并。
4. 合并 `feat/unpacking-toolchain` → `main` 后清理本地分支。
