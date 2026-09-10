# packed-overflow-note（加壳闭源样本 #1：栈缓冲区溢出）

## 登记

| 项 | 内容 |
|---|---|
| 样本名 | `packed-overflow-note`（演示形态：加壳闭源笔记小工具） |
| 类别 | 加壳闭源软件（UPX 壳） |
| 来源 | 本仓库自编教学样本（2026-09-11，分支 `demo/test-fixtures`），非第三方二进制 |
| 授权依据 | `AGENTS.md` §6 “无害样本”定义：仅含确定性栈缓冲区溢出模式，无持久化、无横向移动、无外部网络访问；溢出后果限于本进程段错误，不可用于攻击真实目标 |
| 分发形态 | 仅二进制（`dist/`）；源码保留于 `src/` 供登记溯源 |

## 预期漏洞

- **CWE-120**（栈缓冲区溢出）：函数 `save_note()`，`strcpy(buffer[32], argv[1])` 无界拷贝。
- 触发输入示例（仅引起本进程崩溃）：
  `./packed-overflow-note $(python3 -c "print('A'*128)")` → SIGSEGV（实测 exit 139）。
- 正常路径：`./packed-overflow-note hello` → `note saved: hello`，exit 0。

## 预期分析路径

1. DIE/检测器识别 `UPX!` 签名 → 判定为 UPX 壳（`linux/amd64`，压缩比约 37%）。
2. `upx -d packed-overflow-note` 脱壳（或 `upx -t` 校验完整性）。
3. Ghidra 反编译脱壳 ELF：`main` → `save_note` 伪代码中可见 `strcpy` 到 32 字节栈数组。
4. 语义审计应命中：`strcpy` 目标为固定栈缓冲、长度未校验 → CWE-120 Finding（函数 `save_note`）。

## SHA-256

```
6863d394dd6cb24ece61bfde48e3e9a4159666adb0071387a425e389eb1374c6  dist/packed-overflow-note
```

构建产物清单以 `dist/SHA256SUMS` 为准；重跑 `build.sh` 可复现相同哈希（已验证）。

## 构建

```sh
sh build.sh          # 编译（gcc:13-bookworm）→ UPX 加壳（vulnweaver-binary-tools:fixed）→ 校验
```

可用环境变量覆盖镜像：`VULNWEAVER_CC_IMAGE`、`VULNWEAVER_PACK_IMAGE`。脚本幂等：每次重建 `dist/`；样本行为断言（正常路径 + 崩溃路径）均在一次性容器内执行。
