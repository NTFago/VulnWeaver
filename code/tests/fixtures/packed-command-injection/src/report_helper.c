/*
 * Teaching sample: packed "closed-source" report helper holding three
 * deterministic weaknesses behind a small command dispatch layer:
 *   - CWE-78  OS command injection in run_report()          (original finding)
 *   - CWE-134 uncontrolled format string in export_report() (added 2026-09-12)
 *   - CWE-121 stack buffer overflow in log_event()          (added 2026-09-12)
 *
 * 来源：本仓库自编教学样本（2026-09-11，分支 demo/test-fixtures；
 * 2026-09-12 分支 demo/enrich-fixtures 丰富为多漏洞样本）。
 * 授权依据：AGENTS.md §6 “无害样本”定义——system() 的固定前缀仅调用 echo，
 * 登记的触发载荷仅追加 id/echo 等无害命令；格式串与溢出触发后果限于本地
 * 回显 / 本进程崩溃；无持久化、无横向移动、无外部网络访问。
 *
 * 触发方式（后果均为本地回显或本进程崩溃，见 build.sh 断言）：
 *   ./packed-command-injection "team-a; id"                        -> CWE-78 额外执行 id（无害）
 *   ./packed-command-injection --export "%p %p"                    -> CWE-134 本地回显栈十六进制
 *   ./packed-command-injection --log $(python3 -c "print('A'*300)") -> CWE-121 SIGSEGV
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void print_banner(void) {
    printf("report-helper 1.0 (teaching sample)\n");
}

static int run_report(const char *target) {
    char command[160];
    /* snprintf 有界拷贝：run_report 只保留命令注入一类漏洞，不引入溢出。 */
    int written = snprintf(command, sizeof(command), "echo audit-report-for %s", target);
    if (written < 0) {
        return 1;
    }
    /* CWE-78: user-controlled target is concatenated into a system() call. */
    return system(command);
}

static int export_report(const char *name) {
    printf("export-report: ");
    /* CWE-134: the report name is emitted as the format string itself. */
    printf(name);
    printf("\n");
    return 0;
}

static int log_event(const char *message) {
    char line[64];
    /* CWE-121: message is spliced into a fixed 64-byte stack buffer without
       bounds checks; -fno-stack-protector keeps the crash deterministic. */
    sprintf(line, "log: %s", message);
    printf("%s\n", line);
    return 0;
}

/* 菜单分发层：main 只解析命令字，功能入口由本层进入（main -> dispatch -> 功能函数）。 */
static int dispatch_command(int argc, char **argv) {
    const char *command = argv[1];

    if (strcmp(command, "--export") == 0) {
        if (argc < 3) {
            printf("usage: %s --export <report-name>\n", argv[0]);
            return 1;
        }
        return export_report(argv[2]);
    }
    if (strcmp(command, "--log") == 0) {
        if (argc < 3) {
            printf("usage: %s --log <message>\n", argv[0]);
            return 1;
        }
        return log_event(argv[2]);
    }
    /* 默认命令：对给定目标生成审计报表（原始 CWE-78 路径，保持不变）。 */
    return run_report(command);
}

int main(int argc, char **argv) {
    print_banner();
    if (argc < 2) {
        printf("usage: %s <target-name> | %s --export <report-name> | %s --log <message>\n",
               argv[0], argv[0], argv[0]);
        return 1;
    }
    return dispatch_command(argc, argv);
}
