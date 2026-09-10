# benign-checksum（无害对照样本：NO_FINDINGS 路径）

## 登记

| 项 | 内容 |
|---|---|
| 样本名 | `benign-checksum`（演示形态：FNV-1a 文件摘要工具） |
| 类别 | 无害对照样本 |
| 来源 | 本仓库自编教学样本（2026-09-11，分支 `demo/test-fixtures`） |
| 授权依据 | `AGENTS.md` §6 “无害样本”定义：不含任何已知漏洞模式，仅对授权文件做有界读取并计算摘要；无持久化、无横向移动、无外部网络访问 |

## 预期分析结论

- **无发现（NO_FINDINGS）**：读取长度受 `sizeof(chunk)` 限制、输出使用常量格式串、无 `strcpy`/`system`/`gets` 等危险原语（`build.sh` 通过 `objdump -T` 自动断言无危险导入）。
- 用于演示分析管线的负向路径：不产生 Finding、Task 以 `CLEAN`/`NO_FINDINGS` 收敛，而不是所有样本都必须报漏洞。

## 预期分析路径

DIE/检测器判定未加壳 → Ghidra 反编译：`main` → `fnv1a_file`，循环上界为块大小，`printf` 格式串为常量 → 语义审计不应命中任何 CWE。

## SHA-256

```
d868903c5e11e1df0a7b083014fbe9eec4da2dc1bd09883ffacdd6cb34f2449a  dist/benign-checksum
```

构建产物清单以 `dist/SHA256SUMS` 为准；重跑 `build.sh` 可复现相同哈希（已验证）。

## 构建

```sh
sh build.sh          # 编译（gcc:13-bookworm，-O2）→ 无危险导入断言 + 运行冒烟
```
