# packed-overflow-note（加壳闭源样本 #1：栈溢出 + 堆溢出 + 空指针解引用）

## 登记

| 项 | 内容 |
|---|---|
| 样本名 | `packed-overflow-note`（演示形态：加壳闭源笔记小工具） |
| 类别 | 加壳闭源软件（UPX 壳） |
| 来源 | 本仓库自编教学样本（2026-09-11，分支 `demo/test-fixtures`；2026-09-12 分支 `demo/enrich-fixtures` 丰富为 3 漏洞样本），非第三方二进制 |
| 授权依据 | `AGENTS.md` §6 “无害样本”定义：仅含确定性缓冲区溢出与空指针解引用模式，无持久化、无横向移动、无外部网络访问；漏洞触发后果限于本进程崩溃（SIGSEGV / glibc abort），不可用于攻击真实目标 |
| 分发形态 | 仅二进制（`dist/`）；源码保留于 `src/` 供登记溯源 |
| 结构 | `main → dispatch_command`（菜单分发层）→ `save_note` / `list_notes` / `delete_note`（功能函数） |

## 漏洞登记（3 项）

| CWE | 函数 | 模式 | 触发输入（后果均为本进程崩溃） |
|---|---|---|---|
| CWE-120 | `save_note` | `strcpy(buffer[32], argv[1])` 无界拷贝到栈缓冲 | `./packed-overflow-note $(python3 -c "print('A'*200)")` → SIGSEGV（实测 exit 139） |
| CWE-122 | `list_notes` | `strcpy(listing, filter)` 无界拷贝到 `malloc(1200)` 堆块（1200 字节超出 tcache 上限，使 glibc `free()` 走带相邻块校验的常规路径，崩溃行为确定） | `./packed-overflow-note --list $(python3 -c "print('A'*1400)")` → glibc abort（实测 exit 134） |
| CWE-476 | `delete_note` | `lookup_record()` 对未登记 id 返回 NULL，返回值未检查即 `record->in_use` 解引用 | `./packed-overflow-note --delete 42` → SIGSEGV（实测 exit 139） |

- 正常路径：`./packed-overflow-note hello` → `note saved: hello`；`--list pending` → `listing: pending`；`--delete 1` → `deleted note: 1`（id `1` 命中登记记录），均 exit 0。
- build.sh 断言：三个漏洞的良性路径 + 崩溃路径全部自动验证（崩溃码钉死 139/134/139）。

## 预期分析路径

1. DIE/检测器识别 `UPX!` 签名 → 判定为 UPX 壳（`linux/amd64`）。
2. `upx -d packed-overflow-note` 脱壳（或 `upx -t` 校验完整性）。
3. Ghidra 反编译脱壳 ELF：`main` → `dispatch_command` 分发可见三个功能入口；
   `save_note` 中 `strcpy` 到 32 字节栈数组（CWE-120）、`list_notes` 中 `strcpy`
   到 `malloc` 返回的固定堆块（CWE-122）、`delete_note` 对查找结果未判空即
   解引用（CWE-476）。
4. 语义审计应命中三个 Finding：函数分别为 `save_note` / `list_notes` / `delete_note`。

## SHA-256

```
d6c97d603434847785396cc71d94d5342ab26afd7b8c9485f1f79f46f657bf8c  dist/packed-overflow-note
```

构建产物清单以 `dist/SHA256SUMS` 为准；重跑 `build.sh` 可复现相同哈希
（2026-09-12 Docker 内两遍构建逐字节一致，已验证）。

## 构建

```sh
sh build.sh          # 编译（gcc:13-bookworm）→ UPX 加壳（vulnweaver-binary-tools:fixed）→ 校验
```

可用环境变量覆盖镜像：`VULNWEAVER_CC_IMAGE`、`VULNWEAVER_PACK_IMAGE`。脚本幂等：每次重建 `dist/`；样本行为断言（良性路径 + 崩溃路径）均在一次性容器内执行。
