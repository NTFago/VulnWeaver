# obfuscated-format-string（混淆闭源样本 #1：控制流平坦化 + 格式化字符串）

## 登记

| 项 | 内容 |
|---|---|
| 样本名 | `obfuscated-format-string`（演示形态：混淆闭源许可证校验工具） |
| 类别 | 混淆闭源软件（手写 OLLVM 风格控制流平坦化） |
| 来源 | 本仓库自编教学样本（2026-09-11，分支 `demo/test-fixtures`）；平坦化形状参考 `teaching-samples/ollvm-style-flattened.c`，非第三方 OLLVM 编译产物 |
| 授权依据 | `AGENTS.md` §6 “无害样本”定义：格式化字符串触发后果限于向本地终端回显栈上数据；无持久化、无横向移动、无外部网络访问 |
| 分发形态 | 仅二进制（`dist/`，未加壳 ELF）；源码保留于 `src/` 供登记溯源 |

## 预期漏洞

- **CWE-134**（不受控格式化字符串）：函数 `audit_log()`，`printf(event)` 直接输出用户输入。
- 触发输入示例（本地回显栈数据）：
  `./obfuscated-format-string "%p %p %p"` → 打印栈寄存器内容；`"%x %x %x"` 同理。
- 正常路径：`./obfuscated-format-string LICENSE-1234` → `license accepted`。

## 混淆特征（预期分析路径）

1. 检测未加壳（无 `UPX!` 签名）→ 直接进入反编译。
2. Ghidra 伪代码可见 OLLVM `fla` 形状：`validate_license()` 内 `for(;;)+switch(state)` 分发器、非常量状态转移（`0x4A→0x91→0xB7→0xD2→0xE8/0xC3`）。
3. 反汇编验证：存在经跳转表的间接跳转（`jmp *…`，`build.sh` 已自动断言）。
4. 语义审计应命中：`printf` 首参为用户可控字符串（非常量格式串）→ CWE-134 Finding（函数 `audit_log`，调用链 `main → validate_license → audit_log`）。

## SHA-256

```
c0881f94059bcdee49a594ece3c9f371c082e07b1db4f43cf782297f80193bfb  dist/obfuscated-format-string
```

构建产物清单以 `dist/SHA256SUMS` 为准；重跑 `build.sh` 可复现相同哈希（已验证）。

## 构建

```sh
sh build.sh          # 编译（gcc:13-bookworm）→ 分发器特征与泄漏行为断言（均在一性容器内）
```
