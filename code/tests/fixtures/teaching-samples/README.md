# 教学样本登记

| 文件 | 来源 | 授权依据 | 用途 |
|---|---|---|---|
| `fuzz-overflow.c` | 本仓库自编（2026-09-10，分支 `feat/sprint-final-closeout`） | 自编教学样本，可公开；仅含确定性的栈缓冲区溢出模式，无恶意功能，不可用于攻击真实目标 | T19 AFL++/CASR 模糊测试链路的无害崩溃样本（`vulnweaver-fuzz-entrypoint` 回放） |
| `ollvm-style-flattened.c` | 本仓库自编（2026-09-10，`feat/t28-deobfuscation`） | 自编教学样本，可公开；复现 OLLVM `fla` 的 dispatcher/state-machine 控制流形状，不含恶意功能或外部访问 | T28 混淆识别与可读伪代码恢复回归；明确不是第三方 OLLVM 编译产物 |
| `packed-flattened.c` + `build-packed-sample.sh` | 本仓库自编（2026-09-11） | 自编教学样本，可公开；只对常量数组做算术，无输入、无 I/O、无网络/持久化/提权/文件系统行为 | T27/T28「加壳 + 混淆 → 还原」链路的样本；见下方说明 |

## `packed-flattened.c`：加壳 + 平坦化样本

### 它是什么

一个同时带两层混淆的 ELF 教学样本，两层各对应一个还原阶段：

1. **壳**：`build-packed-sample.sh` 用 UPX 压缩编译产物，解壳前文件里没有真实代码、也没有符号。还原方：`UpxAdapter`（`upx -t` / `upx -d`）。
2. **混淆**：`flattened_checksum()` 写成 OLLVM `fla` 风格的 dispatcher 状态机，而不是它实际代表的那个循环。还原方：`assess_control_flow_flattening()` + `recover_readable_pseudocode()`。

样本带一个**已知答案**，所以「有没有还原出来」是可判定问题，不是主观判断。

### 构建

构建必须在有编译器**和**打包器的环境里做，即 Dev Container（AGENTS.md 4.1）。脚本依赖 `gcc` 与 `upx`，两者都已装进 `code/.devcontainer/Dockerfile`：

```sh
docker compose build dev && docker compose up -d dev
docker compose exec dev sh /workspace/vulnweaver/code/tests/fixtures/teaching-samples/build-packed-sample.sh
```

产物落在 `build/`（已 gitignore，不提交——脚本是它们唯一的来源）：

| 产物 | 说明 |
|---|---|
| `packed-flattened.reference` | `-O0 -g`，未加壳未 strip，**基准真值** |
| `packed-flattened.pre-pack` | `-O0 -s`，加壳前的输入 |
| `packed-flattened.packed` | UPX 加壳后的样本，**待分析对象** |
| `packed-flattened.unpacked` | `upx -d` 的结果，用于证明还原是逐字节的 |

`-O0` 是**承重**的，不是默认值：`-O1` 及以上 GCC 会把状态机折回原本的循环，样本就没有存在意义了。不要为了「优化」而调高它。

### 基准真值

`flattened_checksum()` 的平坦化前语义是一个标准 FNV-1a 32 位哈希，再接一个收尾函数：

```c
uint32_t acc = 0x811c9dc5u;              /* FNV-1a 32-bit offset basis */
for (uint32_t i = 0; i < length; i++) {
    acc ^= (uint32_t)data[i];
    acc *= 0x01000193u;                  /* FNV-1a 32-bit prime */
}
return flatten_mix(acc);                 /* (acc << 5) ^ (acc >> 27) */
```

对 16 字节常量载荷 `kSamplePayload`（`"VulnWeaver-T28"` + NUL + `0xff`）的结果是 `0x0770648E`，作为 `REFERENCE_DIGEST` 写在源码里。

**判定标准**：恢复出的伪代码应当能被认作「对 `length` 字节的 FNV-1a，再调用 `flatten_mix()`」，并且还要恢复出离开 dispatcher 的那一条调用边。不是这个形状，就说明 dispatcher 没被还原。

构建脚本会运行 reference 构建来自检 `REFERENCE_DIGEST`——`main()` 在摘要不符时返回非零，构建即失败，所以该常量不会悄悄过期。脚本**只执行未加壳的 reference**；加壳样本本身只被 UPX 做完整性测试和解压，不执行。

### 已实测的链路事实（2026-09-11）

在本仓库当前环境实测，非推断：

- 打包：`14392 -> 5436` 字节（37.77%，UPX 4.2.2）；`upx -t` 通过；`upx -d` 还原结果与加壳前**逐字节一致**。
- 交叉版本：binary-tools 镜像里的 UPX 4.2.4 能正常 `-t` 解开 4.2.2 的产物，因此打包版本与管线解壳版本不一致不影响本样本。
- **头部识别会漏判**：UPX 4.2.2 与 4.2.4 都会删除 linux/amd64 产物的段头表（`readelf -S` 报 `There are no sections in this file`）。因此 `inspect_binary()` 对本样本返回 `sections=0, packed=False, packer=None`——`_packer_from_sections()` 这一路对 UPX 的 Linux 产物**永远不会命中**（对照未加壳的 reference：`sections=35`）。
- **但还原不依赖上述识别**：`BinaryAnalysisExecutor` 无条件调用 `UpxAdapter`（不以 `metadata.packed` 为门），所以 `upx -t` / `upx -d` 仍会解壳，`aggregate` 由解壳结果置为 `packed=true` / `packer=UPX`。

由此还有一条对既有测试的提示：`tests/binary_analysis/samples.py` 的 `elf64_sample(upx_section=True)` 构造的是带 `UPX0` 段名的**合成** ELF，而 UPX 在 Linux 上并不产出这种形状（PE 产物才会保留 `UPX0`/`UPX1` 段）。该测试覆盖的是解析器对段名的处理，不代表真实 UPX 样本的识别路径。

### 未验证范围

本轮**没有**跑混淆启发式的端到端判定，也**没有**把样本投递给部署栈。特别是：`assess_control_flow_flattening()` 默认 `min_score=0.55`，而

```
score = 0.7 * (successor≥4 的块数 / 总块数) + 0.3 * min(1, 间接跳转数 / 总块数)
```

单一 dispatcher 在真实函数里占块数比例很低，本样本（5 个状态）能否越过 0.55 取决于 Ghidra 实际报出的块划分，**尚未实测**。若要据此断言「样本被判为混淆」，需先跑一次并记录 `ObfuscationAssessment.score` 与 `dispatcher_blocks`。
