# obfuscated-heap-overflow（混淆闭源样本 #2：平坦化 + 不透明谓词 + 字符串编码 + 堆溢出）

## 登记

| 项 | 内容 |
|---|---|
| 样本名 | `obfuscated-heap-overflow`（演示形态：混淆闭源令牌解析工具） |
| 类别 | 混淆闭源软件（手写控制流平坦化 + 不透明谓词 + XOR 字符串常量编码） |
| 来源 | 本仓库自编教学样本（2026-09-11，分支 `demo/test-fixtures`），全部混淆为手写教学形状，非第三方工具产物 |
| 授权依据 | `AGENTS.md` §6 “无害样本”定义：溢出后果限于本进程被 glibc 检测中止（exit 134）或段错误；无持久化、无横向移动、无外部网络访问 |
| 分发形态 | 仅二进制（`dist/`，未加壳 ELF）；源码保留于 `src/` 供登记溯源 |

## 预期漏洞

- **CWE-122**（堆缓冲区溢出）：函数 `parse_token()`，`strcpy(line, token)` 向 `malloc(1200)` 行缓冲无界拷贝（1200 字节超出 tcache 上限，使 glibc `free()` 走带相邻块校验的常规路径，崩溃行为确定）。
- 触发输入示例（仅引起本进程崩溃）：
  `./obfuscated-heap-overflow $(python3 -c "print('A'*1400)")` → glibc abort（实测 exit 134）。
- 正常路径：`./obfuscated-heap-overflow tok` → 打印解码后的 `TOKEN-PARSER` 与 `token: tok`。

## 混淆特征（预期分析路径）

1. 检测未加壳 → 直接进入反编译；`strings` 中找不到明文 `TOKEN-PARSER`（XOR 0x37 编码，运行时还原，`build.sh` 已自动断言）。
2. Ghidra 伪代码可见 `run_pipeline()` 内 `for(;;)+switch(state)` 分发器（反汇编存在 `jmp *…` 间接跳转）。
3. `opaque_gate(n)` 为恒真不透明谓词（`n*(n-1)` 恒为偶数），else 分支是不可达诱饵——解混淆/常量传播应可化简。
4. 语义审计应命中：`strcpy` 目标为固定大小堆分配且长度未校验 → CWE-122 Finding（函数 `parse_token`）。

## SHA-256

```
e9791e200e7be08a366575c0979eeeda8d381854022aaab989555cc6ef8c4548  dist/obfuscated-heap-overflow
```

构建产物清单以 `dist/SHA256SUMS` 为准；重跑 `build.sh` 可复现相同哈希（已验证）。

## 构建

```sh
sh build.sh          # 编译（gcc:13-bookworm）→ 混淆特征与崩溃断言（均在一次性容器内）
```
