# packed-command-injection（加壳闭源样本 #2：命令注入）

## 登记

| 项 | 内容 |
|---|---|
| 样本名 | `packed-command-injection`（演示形态：加壳闭源报表小工具） |
| 类别 | 加壳闭源软件（UPX 壳） |
| 来源 | 本仓库自编教学样本（2026-09-11，分支 `demo/test-fixtures`），非第三方二进制 |
| 授权依据 | `AGENTS.md` §6 “无害样本”定义：`system()` 固定前缀仅调用 `echo`，登记触发载荷仅追加 `id`/`echo` 等无害命令；无持久化、无横向移动、无外部网络访问 |
| 分发形态 | 仅二进制（`dist/`）；源码保留于 `src/` 供登记溯源 |

## 预期漏洞

- **CWE-78**（OS 命令注入）：函数 `run_report()`，用户输入经 `snprintf` 拼接进 `system(command)`。
- 触发输入示例（仅执行无害命令）：
  `./packed-command-injection "team-a; id"` → 打印报表行并额外执行 `id`（当前用户信息）。
- 正常路径：`./packed-command-injection team-a` → `audit-report-for team-a`。

## 预期分析路径

1. DIE/检测器识别 `UPX!` 签名 → 判定为 UPX 壳（`linux/amd64`，压缩比约 38%）。
2. `upx -d` 脱壳。
3. Ghidra 反编译：`run_report` 伪代码可见 `snprintf` 构造 `"echo audit-report-for %s"` 后传入 `system`。
4. 语义审计应命中：`system()` 参数含用户可控拼接 → CWE-78 Finding（函数 `run_report`）。

## SHA-256

```
1958f5dcc65c4337f35b2a846f39f8a9e679e63476b105c973d1921ec5cf1a2b  dist/packed-command-injection
```

构建产物清单以 `dist/SHA256SUMS` 为准；重跑 `build.sh` 可复现相同哈希（已验证）。

## 构建

```sh
sh build.sh          # 编译（gcc:13-bookworm）→ UPX 加壳（vulnweaver-binary-tools:fixed）→ 校验
```

构建脚本内的注入断言只追加 `echo` 标记（`INJECTED_MARKER_OK`），符合无害红线。
