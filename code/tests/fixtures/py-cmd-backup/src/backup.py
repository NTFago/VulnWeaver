"""Teaching sample: source-level OS command injection (CWE-78).

来源：本仓库自编教学样本（2026-09-11，分支 demo/test-fixtures）。
授权依据：AGENTS.md §6 “无害样本”定义——命令模板固定前缀仅调用 echo，
登记的触发载荷仅追加 id/echo 等无害命令；无持久化、无横向移动、
无外部网络访问。

预期漏洞：backup() 将用户输入拼进 shell=True 的命令行（CWE-78）。
触发方式：
    python backup.py notes.txt            # 正常路径
    python backup.py "notes.txt; id"      # 注入（无害）
"""

import subprocess
import sys


def backup(target: str) -> int:
    """CWE-78: user-controlled target is concatenated into a shell command."""
    command = f"echo backup-of {target}"
    return subprocess.run(command, shell=True, check=False).returncode


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: backup.py <target-name>")
        return 1
    return backup(argv[1])


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
