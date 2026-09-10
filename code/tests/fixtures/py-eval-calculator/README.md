# py-eval-calculator（源码样本：eval 代码注入）

## 登记

| 项 | 内容 |
|---|---|
| 样本名 | `py-eval-calculator`（演示形态：表达式计算器） |
| 类别 | 源码样本（Python） |
| 来源 | 本仓库自编教学样本（2026-09-11，分支 `demo/test-fixtures`） |
| 授权依据 | `AGENTS.md` §6 “无害样本”定义：eval 仅在本地进程内求值，登记触发载荷仅调用 `os.system` 的 `id`/`echo` 等无害命令；无持久化、无横向移动、无外部网络访问 |

## 预期漏洞

- **CWE-95**（eval 代码注入）：函数 `evaluate()`，`eval(expression)` 直接求值用户输入。
- 触发输入示例（仅执行无害命令）：
  `python src/calculator.py "__import__('os').system('id')"` → 打印当前用户信息。
- 正常路径：`python src/calculator.py "2+2"` → `4`。

## 预期分析路径

源码审计（source-analysis Worker）应命中：`eval()` 调用点参数来自 `sys.argv` → CWE-95 Finding（函数 `evaluate`）。

## 校验与构建

```sh
sh build.sh          # python:3.12-slim 内 py_compile 语法校验 + 正常路径冒烟
```

## SHA-256

```
a789ab74e4ccd929530ce885bc2c5205583a67fc758a43d29ca626a8571042a7  src/calculator.py
```

以 `dist/SHA256SUMS` 为准；Python 样本无编译产物，`dist/` 仅记录已校验源码摘要。
