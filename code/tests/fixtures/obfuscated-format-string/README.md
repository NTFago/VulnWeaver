# obfuscated-format-string（混淆闭源样本 #1：平坦化 + 格式化字符串 + 弱校验 + 栈溢出）

## 登记

| 项 | 内容 |
|---|---|
| 样本名 | `obfuscated-format-string`（演示形态：混淆闭源许可证校验工具） |
| 类别 | 混淆闭源软件（手写 OLLVM 风格控制流平坦化，校验路径含二级嵌套子状态机） |
| 来源 | 本仓库自编教学样本（2026-09-11，分支 `demo/test-fixtures`；2026-09-12 分支 `demo/enrich-fixtures` 丰富为 3 漏洞样本）；平坦化形状参考 `teaching-samples/ollvm-style-flattened.c`，非第三方 OLLVM 编译产物 |
| 授权依据 | `AGENTS.md` §6 “无害样本”定义：格式化字符串触发后果限于向本地终端回显栈上数据，溢出后果限于本进程崩溃；无持久化、无横向移动、无外部网络访问 |
| 分发形态 | 仅二进制（`dist/`，未加壳 ELF）；源码保留于 `src/` 供登记溯源 |
| 结构 | `main` →（默认）`validate_license`（外层校验状态机，内嵌 `license_tier` 二级子状态机）→ `audit_log`；`main → sync_config`（`--sync-config` 命令） |

## 漏洞登记（3 项）

| CWE | 函数 | 模式 | 触发输入（后果均为本地回显或授予等级） |
|---|---|---|---|
| CWE-134 | `audit_log` | `printf(event)` 直接以用户输入作格式串 | `./obfuscated-format-string "%p %p %p"` → 打印栈寄存器内容；`"%x %x %x"` 同理（本地回显） |
| CWE-287 | `validate_license` | 弱身份校验：唯一否定条件是首字符 `-`，任意其他 key 均放行，并按首字符授予 `pro`/`enterprise`/`standard` 等级（可观察的非安全后果：打印 `license tier: …`）。原宽松校验自 2026-09-12 起登记为设计内弱点 | `./obfuscated-format-string totally-not-a-license` → `license tier: standard` + `license accepted`（确定性）；`E-CORP-9` → `license tier: enterprise` |
| CWE-121 | `sync_config` | `strcpy(config_path[64], path)` 无界拷贝到 64 字节栈缓冲 | `./obfuscated-format-string --sync-config $(python3 -c "print('A'*300)")` → SIGSEGV（实测 exit 139） |

- 正常路径：`./obfuscated-format-string LICENSE-1234` → `license tier: standard` + `license accepted`；`--sync-config etc/app.conf` → `syncing config from etc/app.conf`，均 exit 0。
- build.sh 断言：三个漏洞的良性路径 + 触发路径全部自动验证（CWE-121 崩溃码钉死 139）。

## 混淆特征（预期分析路径）

1. 检测未加壳（无 `UPX!` 签名）→ 直接进入反编译。
2. 两级嵌套平坦化：`validate_license()` 外层状态机
   （`0x4A→0x91→0xB7→0xD2→0xE8/0xC3`）在 `STATE_AUDIT` 调用二级子状态机
   `license_tier()`（`0x27→0x5E→0xB1→0xF3`）；反汇编存在经跳转表的间接跳转
   （`jmp *…`，`build.sh` 已自动断言）。
3. 语义审计应命中三个 Finding：`printf` 首参为用户可控字符串 → CWE-134
   （函数 `audit_log`，调用链 `main → validate_license → audit_log`）；弱校验
   任意放行并授予等级 → CWE-287（函数 `validate_license`）；`strcpy` 到固定
   64 字节栈缓冲 → CWE-121（函数 `sync_config`）。

## SHA-256

```
0b50ae99072ad85472e7f5bb9f0ccc57b7955da4a07450394aca14a1fb36dc53  dist/obfuscated-format-string
```

构建产物清单以 `dist/SHA256SUMS` 为准；重跑 `build.sh` 可复现相同哈希
（2026-09-12 Docker 内两遍构建逐字节一致，已验证）。

## 构建

```sh
sh build.sh          # 编译（gcc:13-bookworm）→ 分发器特征与行为断言（均在一次性容器内）
```
