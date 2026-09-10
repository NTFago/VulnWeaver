"""Teaching sample: source-level code injection via eval() (CWE-95).

来源：本仓库自编教学样本（2026-09-11，分支 demo/test-fixtures）。
授权依据：AGENTS.md §6 “无害样本”定义——eval 仅在本地进程内求值；
登记的触发载荷仅调用 os.system 的 id/echo 等无害命令；无持久化、
无横向移动、无外部网络访问。

预期漏洞：evaluate() 直接 eval 用户输入（CWE-95 代码注入）。
触发方式：
    python calculator.py "2+2"                                # 正常路径
    python calculator.py "__import__('os').system('id')"      # 注入（无害）
"""

import sys


def evaluate(expression: str):
    """CWE-95: user-controlled expression is passed to eval()."""
    return eval(expression)


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: calculator.py <expression>")
        return 1
    try:
        result = evaluate(argv[1])
    except Exception as exc:  # 教学样本：把求值失败转成可读输出
        print(f"error: {exc}")
        return 1
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
