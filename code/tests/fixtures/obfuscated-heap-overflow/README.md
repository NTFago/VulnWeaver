# obfuscated-heap-overflow（混淆闭源样本 #2：两级状态机 + 堆溢出 + 双重释放）

## 登记

| 项 | 内容 |
|---|---|
| 样本名 | `obfuscated-heap-overflow`（演示形态：混淆闭源令牌解析工具） |
| 类别 | 混淆闭源软件（手写两级嵌套控制流平坦化 + 不透明谓词 + 按位置变键的 XOR 字符串常量编码） |
| 来源 | 本仓库自编教学样本（2026-09-11，分支 `demo/test-fixtures`；2026-09-12 分支 `demo/enrich-fixtures` 丰富为 2 漏洞样本），全部混淆为手写教学形状，非第三方工具产物 |
| 授权依据 | `AGENTS.md` §6 “无害样本”定义：漏洞触发后果限于本进程被 glibc 检测中止（exit 134）或段错误；无持久化、无横向移动、无外部网络访问 |
| 分发形态 | 仅二进制（`dist/`，未加壳 ELF）；源码保留于 `src/` 供登记溯源 |
| 结构 | `main → run_session`（外层会话状态机）→ `parse_token`（内层解析状态机）/ `free_session`（会话释放路径） |

## 漏洞登记（2 项）

| CWE | 函数 | 模式 | 触发输入（后果均为本进程崩溃） |
|---|---|---|---|
| CWE-122 | `parse_token` | `strcpy(line, token)` 向 `malloc(1200)` 行缓冲无界拷贝（1200 字节超出 tcache 上限，使 glibc `free()` 走带相邻块校验的常规路径，崩溃行为确定） | `./obfuscated-heap-overflow $(python3 -c "print('A'*1400)")` → glibc abort（实测 exit 134） |
| CWE-415 | `free_session` | 同一 lease 指针被 `free()` 两次，glibc tcache 重放检测确定性 abort（`free(): double free detected in tcache 2`） | `./obfuscated-heap-overflow --free s1` → abort（实测 exit 134） |

- 正常路径：`./obfuscated-heap-overflow tok` → 打印解码后的 `TOKEN-PARSER` 与 `token: tok`，exit 0。
- build.sh 断言：两个漏洞的良性/触发路径全部自动验证（CWE-415 崩溃码钉死 134）。

## 混淆特征（预期分析路径）

1. 检测未加壳 → 直接进入反编译；`strings` 中找不到明文 `TOKEN-PARSER` /
   `SESSION-VAULT`（XOR 密钥按字节位置变化 `0x37+i`，运行时还原，`build.sh`
   已自动断言）。
2. 两级嵌套状态机：外层 `run_session()`（会话状态：INIT→GATE→OPEN→PARSE/FREE→DONE）
   调用内层 `parse_token()` 解析状态机（DECODE→ALLOC→COPY→EMIT→FINISH）；
   反汇编存在经跳转表的间接跳转（`jmp *…`，`build.sh` 已自动断言）。
3. 不透明谓词三族：`opaque_gate(n)`/`opaque_pair(n)` 恒真（相邻整数乘积恒为偶数）、
   `opaque_false(n)` 恒假（`n*(n-1)` 除 3 只余 0 或 2）；else/then 反向分支均为
   不可达诱饵——解混淆/常量传播应可化简。
4. 语义审计应命中两个 Finding：`strcpy` 目标为固定大小堆分配且长度未校验 →
   CWE-122（函数 `parse_token`）；同一指针两次 `free` → CWE-415（函数 `free_session`）。

## SHA-256

```
980411e766217382e125f68b45402f464c63514e624264b9483778dc836510d0  dist/obfuscated-heap-overflow
```

构建产物清单以 `dist/SHA256SUMS` 为准；重跑 `build.sh` 可复现相同哈希
（2026-09-12 Docker 内两遍构建逐字节一致，已验证）。

## 构建

```sh
sh build.sh          # 编译（gcc:13-bookworm）→ 混淆特征与崩溃断言（均在一次性容器内）
```
