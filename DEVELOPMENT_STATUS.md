# DEVELOPMENT STATUS

> 轻量交接台账。稳定规则与安全红线见 `AGENTS.md`；历史课设阶段的任务明细见 Git 历史、PR 与 `code/docs/progress/`。

更新时间：2026-09-28（Asia/Shanghai）

## 当前焦点

系统定位已从课设验证升级为**面向真实世界样本的长线漏洞挖掘智能体系统**（见 `AGENTS.md` 与 ADR-028）。当前主线：补齐真实样本分析的第一道门槛——通用脱壳/重建工具链。

部署栈已在本分支上**全部重建并运行**（postgres/redis/api/orchestrator/dispatcher/analysis-worker/sandbox-runner/web/binary-tools 全部 Up），模型经 Web 设置接入（DeepSeek），栈内端到端已通过（见验证记录）。

## 进行中

| 事项 | 负责人 / 分支 | 状态 |
|---|---|---|
| T46 分层脱壳工具链（UPX/de4dotEx/unipacker/XOR 恢复/LIEF 重建 + `binary-unpack` 沙箱工具） | ZCode / `feat/unpacking-toolchain` | **全部完成**：定向测试、ruff/pyright、镜像构建、容器内冒烟、部署栈内 worker→沙箱→派生工件→模型审计→报告 全链实测通过（`scripts/e2e_unpack_chain.py` 可复跑） |

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
| 2026-09-28 | T46 部署栈内全链 E2E（`code/scripts/e2e_unpack_chain.py`，连续三跑全绿） | 上传自制 XOR 壳 ELF → `import`/`semantic_audit`/`report` 三 Job 全部 succeeded；`xor-recovered-binary` 派生摘要与内层 ELF 逐字节一致；**analysis 的 parent 即脱壳镜像**；模型（deepseek-flash）驱动的语义审计与报告真实产出 |
| 2026-09-28 | 部署栈重建 | 6 个服务镜像 + binary-tools 重建成功；期间修复**全新卷权限缺陷**：root 运行的一次性 migrate 服务初始化 CAS store 时把 `objects/sha256` 建成 root 所有，api(10001) 上传必 EACCES——artifact-init 现已预建该目录（compose.yaml），旧卷 chown 修复 |
| 2026-09-28 | T46 定向测试（Linux 容器 python:3.12-slim + uv 0.10，`uv sync --all-packages --no-editable --group dev`） | `tests/binary_analysis` **54 passed / 3 skipped**（跳过项为 PostgreSQL opt-in，与基线一致）；`tests/sandbox_runner` + `tests/contracts` + `tests/tool_runtime` **44 passed / 1 skipped**（Docker runtime opt-in）；`ruff check .` 通过；`uv lock` 纳入 lief 0.17.6 / unipacker 1.0.8 / unicorn-unipacker 1.0.3b7 |
| 2026-09-28 | pyright（node:24-slim 容器，pyright 1.1.413） | **0 errors**（lief 无存根问题以 `importlib.import_module` 隔离；跨模块私有名已提升为公开助手名） |
| 2026-09-28 | T46 全量测试 | `pytest -n 4`：401 passed / 2 failed（reporting 的 weasyprint 用例，装上 pango 后复跑 **10 passed**，纯环境缺失）/ 173 skipped（PG/Docker opt-in，本机临时容器无对应服务；定向四套件 98 passed） |
| 2026-09-28 | T46 镜像与容器内端到端 | `vulnweaver-binary-tools:fixed` 构建成功（mono-complete + de4dotEx 3.10.0 net48 + `--extra unpack`）；容器内 `--mode unpack` 对自制 XOR 壳 ELF 实测：UPX 探测→not_upx_packed 降级→**xor-recovery 命中**，`unpacked.bin` 与内层 ELF sha256 逐字节一致（`316f0550…`），报告含完整 methods/tool_runs/digests |
| 2026-09-11 | T45/T45-A~F 全量门禁 | `pytest` 556 passed / 5 skipped；ruff、pyright 0 错误；部署栈 UPX 加壳样本端到端通过（历史基线，栈现已清空） |

## 下一步

1. **合并与推送**：`feat/unpacking-toolchain`（5 个提交）待用户确认后推送并合并入 `main`。
2. **真实壳样本扩展验证**：MPRESS/PECompact 样本走 unipacker、ConfuserEx/.NET 样本走 de4dotEx——单测与合成样本已覆盖逻辑，真实壳的成功率需要真实样本回归。
3. **长线分析能力**（目标主线）：多天尺度任务的检查点/断点续跑、任务级分析历史的增量深挖（Finding 驱动的二轮调查已具备，跨 Job 的长线编排是下一块拼图）。
4. 首跑注册的 API 账号 `vw-e2e`（密码在测试脚本常量中）仅用于联调，正式使用时建议改密或换账号。
