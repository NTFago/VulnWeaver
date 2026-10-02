# packed-command-injection（加壳闭源样本 #2：命令注入 + 格式化字符串 + 栈溢出）

## 登记

| 项 | 内容 |
|---|---|
| 样本名 | `packed-command-injection`（演示形态：加壳闭源报表小工具） |
| 类别 | 加壳闭源软件（UPX 壳） |
| 来源 | 本仓库自编教学样本（2026-09-11，分支 `demo/test-fixtures`；2026-09-12 分支 `demo/enrich-fixtures` 丰富为 3 漏洞样本），非第三方二进制 |
| 授权依据 | `AGENTS.md` §6 “无害样本”定义：`system()` 固定前缀仅调用 `echo`，登记触发载荷仅追加 `id`/`echo` 等无害命令；格式串触发后果限于本地回显，溢出后果限于本进程崩溃；无持久化、无横向移动、无外部网络访问 |
| 分发形态 | 仅二进制（`dist/`）；源码保留于 `src/` 供登记溯源 |
| 结构 | `main → dispatch_command`（菜单分发层）→ `run_report` / `export_report` / `log_event`（功能函数） |

## 漏洞登记（3 项）

| CWE | 函数 | 模式 | 触发输入（后果均为本地回显或本进程崩溃） |
|---|---|---|---|
| CWE-78 | `run_report` | 用户输入经 `snprintf` 拼接进 `system(command)` | `./packed-command-injection "team-a; id"` → 打印报表行并额外执行 `id`（无害） |
| CWE-134 | `export_report` | `printf(name)` 以用户输入作格式串 | `./packed-command-injection --export "%p %p %p"` → 本地回显栈数据（如 `0x722d… (nil) (nil)`） |
| CWE-121 | `log_event` | `sprintf(line[64], "log: %s", message)` 无界拷贝到 64 字节栈缓冲 | `./packed-command-injection --log $(python3 -c "print('A'*300)")` → SIGSEGV（实测 exit 139） |

- 正常路径：`./packed-command-injection team-a` → `audit-report-for team-a`；`--export plain-name`、`--log backup-done` 均 exit 0。
- build.sh 断言：三个漏洞的良性路径 + 触发路径全部自动验证（崩溃码钉死 139，`%p` 泄漏断言含 `0x…` 十六进制）。

## 预期分析路径

1. DIE/检测器识别 `UPX!` 签名 → 判定为 UPX 壳（`linux/amd64`）。
2. `upx -d` 脱壳。
3. Ghidra 反编译：`dispatch_command` 分发三个功能入口；`run_report` 可见
   `snprintf` 构造 `"echo audit-report-for %s"` 后传入 `system`（CWE-78）；
   `export_report` 中 `printf` 首参为用户可控字符串（CWE-134）；`log_event`
   中 `sprintf` 目标为固定 64 字节栈缓冲且长度未校验（CWE-121）。
4. 语义审计应命中三个 Finding：函数分别为 `run_report` / `export_report` / `log_event`。

## SHA-256

```
5159afe9e46b239e7790dcd6f41a9dccdf4ff9ff3f3b5a288025510f950eb2bc  dist/packed-command-injection
```

构建产物清单以 `dist/SHA256SUMS` 为准；重跑 `build.sh` 可复现相同哈希
（2026-09-12 Docker 内两遍构建逐字节一致，已验证）。

## 构建

```sh
sh build.sh          # 编译（gcc:13-bookworm）→ UPX 加壳（vulnweaver-binary-tools:fixed）→ 校验
```

构建脚本内的注入断言只追加 `echo` 标记（`INJECTED_MARKER_OK`），符合无害红线。
