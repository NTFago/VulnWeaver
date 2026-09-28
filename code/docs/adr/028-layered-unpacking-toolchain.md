# ADR-028：分层静态脱壳工具链与 binary-unpack 沙箱工具

- 状态：已接受
- 日期：2026-09-28
- 相关：ADR-025（移除计算资源限制）、ADR-027（智能体驱动审计）

## 背景

系统目标从课设验证扩展为对真实世界样本的长线漏洞挖掘。真实样本的第一道现实门槛是壳：目前脱壳只有 `upx -d` 一条路，`.NET` 混淆、常见商业/开源 PE 壳、自制 ELF 壳全部落在能力之外——加壳样本的分析要么 partial、要么干脆分析的是壳本身。互联网上成熟的通用做法是四类策略的组合：

| 壳类型 | 工具 | 性质 |
|---|---|---|
| UPX（PE/ELF） | `upx -d`（已有） | 纯静态 |
| .NET 打包/混淆（ConfuserEx、.NET Reactor、Babel 等） | de4dotEx（GDATA 维护 fork，net48 构建 + mono） | 纯静态 CIL 变换 |
| 常见原生 PE 壳（MPRESS、PECompact 等） | unipacker（Unicorn 指令级模拟脱壳 stub，重建 PE 与 IAT） | 翻译式模拟 |
| 自制壳（高熵区 XOR） | 自研已知明文恢复 + 节表/程序头定位 | 纯静态 |

外加 LIEF 作为重建层：对 dump 出来头破损的 PE 重新序列化为结构合法的容器（经典 dump→重建流程中 Scylla 一类的角色；IAT 重建由 unipacker 在模拟时完成）。

## 决策

### 1. 脱壳是策略链，不是单工具

`UnpackerChain`（`vulnweaver_binary_analysis/unpacking.py`）按轮次执行：每轮遍历适用（`supports` 按格式/架构/壳信号分发）的解壳器，取第一个**通过验收**的候选；候选必须能被严格解析器解析为容器、与输入摘要不同、大小在界内，必要时先经 LIEF 修复再验收。轮次在上限（默认 4）内重复直至图像不再呈现加壳特征——**多层壳逐层剥离**是链的固有行为。验收用的原始摘要锚定链条起点，防止解壳器把输入原样吐回造成假成功。

### 2. 重工具只进 binary-tools 镜像，经新沙箱工具 `binary-unpack` 暴露

worker 本地链保持廉价（UPX + 纯 Python XOR 恢复）。当本地链未产出且样本仍判定加壳时，executor 通过既有的 `SandboxRequest` 协议发起 `binary-unpack`（与 `binary-facts` 共用 binary-tools 镜像摘要，新增独立 ToolSpec 与命令 profile）：容器内运行完整四策略链，回传 `binary-unpack.json` 报告 + `unpacked.bin`。worker 校验报告摘要与 CAS 对象一致后登记派生工件——沿用现有的内容寻址、父版本与生成配置（`format`/`tool`/`methods`/`rounds`）不可变工件语义。

de4dotEx 取 GDATA 官方 release 的 net48 构建（3.10.0），镜像内以 mono 运行，路径经 `DE4DOT_EXECUTABLE` 注入；unipacker 与 LIEF 声明为 `vulnweaver-binary-analysis` 的 `unpack` 可选依赖，仅 binary-tools 镜像安装（`uv sync --extra unpack`），worker 镜像不增重。

### 3. 模拟与静态的边界不变

unipacker 对脱壳 stub 的 Unicorn 模拟与 angr 的 VEX 翻译执行同类：不落地原生执行，且同样只发生在经 sandbox-runner 启动（禁网、只读输入、非 root、一次性）的分析容器内。自制壳 XOR 恢复与 de4dot 是纯静态字节/CIL 变换。**原生执行样本仍 exclusively 属于 Sandbox Runner 的动态管线，本决策未移动该边界。**

### 4. CLR 识别进头解析器

`inspect_binary` 对 PE 解析数据目录 14（CLR runtime header），`BinaryMetadata.dotnet` 据此分发 de4dot；.NET 样本不再被当作普通原生 PE 处理。

## 后果

- binary-tools 镜像显著增大（mono-complete ≈ 500MB）。这是 .NET 能力的现实成本；镜像内工具均为固定版本（de4dotEx 3.10.0、DIE 3.21、Ghidra 12.1.3）。
- 派生工件格式新增 `dotnet-cleaned-assembly`、`emulated-unpacked-binary`、`xor-recovered-binary`；`upx-unpacked-binary` 保持原名，既有溯源不受影响。
- 脱壳成功后 `packed=true/packer=<壳名>` 语义保持描述**输入**（沿用 UPX 路径既有行为）；是否仍加壳记录在生成配置与工具运行里。
- XOR 恢复对「节表被剥掉的加壳 ELF」走程序头回退定位载荷区——这是自制 ELF 壳的常见形态。

## 未决

- `binary-unpack` 的真实镜像端到端（投递 MPRESS/ConfuserEx 样本）尚未执行：单测覆盖链分发、验收、降级与报告解析，容器内四策略对真实壳的行为待部署验证。
- unipacker 的 `unicorn-unipacker` fork 在部分平台只有源码包；当前锁定版本在 linux/amd64 解析正常，其他平台需复核。
- LIEF 重建目前只做「再序列化修复头」；如遇到 IAT 未被 unipacker 完整重建的真实 dump，再评估是否引入显式导入表重建。

## 验证

Linux 容器（python:3.12-slim + uv 0.10）：`uv lock` 成功纳入 lief 0.17.6 / unipacker 1.0.8 / unicorn-unipacker 1.0.3b7；`tests/binary_analysis` 定向测试覆盖：链首轮接受/同摘要拒绝/垃圾候选拒绝/嵌套壳两轮剥离、无节表 XOR 壳恢复（含 PHDR 回退）与无载荷降级、de4dot 的 mono 调用与 `-cleaned` 产物拾取、unipacker CLI 调用与 dump 拾取及缺执行文件降级、UPX 协议包装、LIEF 禁用短路、CLR 目录检测、`binary-unpack` 沙箱报告往返与摘要不匹配拒绝。
