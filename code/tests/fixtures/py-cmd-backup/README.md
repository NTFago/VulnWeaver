# py-cmd-backup（源码样本：shell 命令注入）

## 登记

| 项 | 内容 |
|---|---|
| 样本名 | `py-cmd-backup`（演示形态：备份小工具） |
| 类别 | 源码样本（Python） |
| 来源 | 本仓库自编教学样本（2026-09-11，分支 `demo/test-fixtures`） |
| 授权依据 | `AGENTS.md` §6 “无害样本”定义：命令模板固定前缀仅调用 `echo`，登记触发载荷仅追加 `id`/`echo` 等无害命令；无持久化、无横向移动、无外部网络访问 |

## 预期漏洞

- **CWE-78**（OS 命令注入）：函数 `backup()`，f-string 拼接用户输入后以 `shell=True` 执行。
- 触发输入示例（仅执行无害命令）：
  `python src/backup.py "notes.txt; id"` → 打印 `backup-of notes.txt` 并额外执行 `id`。
- 正常路径：`python src/backup.py notes.txt` → `backup-of notes.txt`。

## 预期分析路径

源码审计应命中：`subprocess.run(..., shell=True)` 参数含用户可控拼接 → CWE-78 Finding（函数 `backup`）。

## 校验与构建

```sh
sh build.sh          # python:3.12-slim 内 py_compile 语法校验 + 正常路径冒烟
```

## SHA-256

```
fc5f288a3908c9868696039cd25e280b54510aad2d879f4f2b6321a8257b0d59  src/backup.py
```

以 `dist/SHA256SUMS` 为准；Python 样本无编译产物，`dist/` 仅记录已校验源码摘要。
