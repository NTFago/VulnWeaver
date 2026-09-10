# 测试样例索引（fixtures）

本目录收容漏洞挖掘系统的演示与分析测试样本。全部样本为**本仓库自编教学样本**，可公开；
依据 `AGENTS.md` §6 “无害样本”定义构建：不含真实恶意功能（无持久化、无横向移动、
无外部网络访问），漏洞触发后果限于本地崩溃/本地回显/无害命令输出，不可用于攻击真实目标。

大作业测试覆盖对应关系（见仓库根 `大作业要求.txt`）：

- **2 种加壳闭源软件** → `packed-overflow-note`、`packed-command-injection`
- **2 种混淆闭源软件** → `obfuscated-format-string`、`obfuscated-heap-overflow`
- 源码审计路径 → `py-eval-calculator`、`py-cmd-backup` 及 `teaching-samples/`
- 无漏洞对照（NO_FINDINGS 路径）→ `benign-checksum`

## 样本矩阵

| 样本 | 类别 | 漏洞 CWE | 漏洞函数 | 构建方式 | 分发产物 SHA-256 |
|---|---|---|---|---|---|
| `packed-overflow-note` | 加壳（UPX 4.2.4） | CWE-120 | `save_note`（strcpy → 栈 buf[32]） | gcc:13-bookworm 编译 + vulnweaver-binary-tools:fixed 加壳 | `6863d394…eb1374c6` |
| `packed-command-injection` | 加壳（UPX 4.2.4） | CWE-78 | `run_report`（system 拼接输入） | 同上 | `1958f5dc…5cf1a2b` |
| `obfuscated-format-string` | 混淆（手写控制流平坦化） | CWE-134 | `audit_log`（printf 用户输入） | gcc:13-bookworm 编译（平坦化在源码内） | `c0881f94…0193bfb` |
| `obfuscated-heap-overflow` | 混淆（平坦化 + 不透明谓词 + XOR 字符串编码） | CWE-122 | `parse_token`（strcpy → malloc(1200)） | 同上 | `e9791e20…6ef8c4548` |
| `py-eval-calculator` | 源码（Python） | CWE-95 | `evaluate`（eval 用户输入） | 无需编译；py_compile 校验 | `a789ab74…571042a7` |
| `py-cmd-backup` | 源码（Python） | CWE-78 | `backup`（shell=True 拼接输入） | 同上 | `fc5f288a…8257b0d59` |
| `benign-checksum` | 无害对照 | 无（NO_FINDINGS） | — | gcc:13-bookworm 编译（-O2） | `d868903c…cb34f2449a` |

每个样本目录结构：`src/`（源码，登记溯源）、`build.sh`（幂等构建 + 行为断言）、
`dist/`（分发产物二进制与 `SHA256SUMS`）、`README.md`（登记表、触发输入、预期分析路径）。

一键构建：`sh build-all.sh`（样本行为断言全部在一次性容器内执行，宿主机不运行样本）。
镜像可用环境变量覆盖：`VULNWEAVER_CC_IMAGE`（默认 `gcc:13-bookworm`）、
`VULNWEAVER_PACK_IMAGE`（默认 `vulnweaver-binary-tools:fixed`）、
`VULNWEAVER_PY_IMAGE`（默认 `python:3.12-slim`）。

## 既有样本（登记沿用各自 README）

| 样本 | 类别 | 用途 |
|---|---|---|
| `teaching-samples/fuzz-overflow.c` | 源码（C，CWE-120 模式） | AFL++/CASR 模糊测试链路回放样本 |
| `teaching-samples/ollvm-style-flattened.c` | 源码（C，平坦化形状） | T28 混淆识别与伪代码恢复回归；`obfuscated-*` 样本的形状参考 |
| `proof/smoke.py` | 其他 | 复核链路冒烟数据 |

## 构建与验证记录（2026-09-11，分支 `demo/test-fixtures`）

- Docker 内实际构建全部样本，`build-all.sh` 完整重跑两次，`dist/` 哈希逐字节一致（可复现）。
- 加壳类：`upx -t` 通过、`strings` 含 `UPX!`；溢出样本崩溃断言 exit 139（SIGSEGV）。
- 混淆类：反汇编含 `jmp *` 间接跳转（switch 分发器）、`strings` 无明文 `TOKEN-PARSER`；堆溢出崩溃断言 exit 134（glibc abort）。
- Python 类：`python -m py_compile` 通过 + 正常路径冒烟。
- 对照样本：`objdump -T` 无危险导入，运行输出 8 位摘要。
