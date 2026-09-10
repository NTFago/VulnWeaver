/*
 * Teaching sample: packed "closed-source" report helper with an OS command
 * injection (CWE-78).
 *
 * 来源：本仓库自编教学样本（2026-09-11，分支 demo/test-fixtures）。
 * 授权依据：AGENTS.md §6 “无害样本”定义——system() 的固定前缀仅调用
 * echo，登记的触发载荷仅追加 id/echo 等无害命令；无持久化、无横向移动、
 * 无外部网络访问。
 *
 * 预期漏洞：run_report() 将用户输入拼接到传给 system() 的命令行（CWE-78）。
 * 触发方式：./packed-command-injection "team-a; id"  -> 额外执行 id（无害）
 */
#include <stdio.h>
#include <stdlib.h>

static void print_banner(void) {
    printf("report-helper 1.0 (teaching sample)\n");
}

static int run_report(const char *target) {
    char command[160];
    /* snprintf 有界拷贝：本样本只保留命令注入一类漏洞，不引入溢出。 */
    int written = snprintf(command, sizeof(command), "echo audit-report-for %s", target);
    if (written < 0) {
        return 1;
    }
    /* CWE-78: user-controlled target is concatenated into a system() call. */
    return system(command);
}

int main(int argc, char **argv) {
    print_banner();
    if (argc < 2) {
        printf("usage: %s <target-name>\n", argv[0]);
        return 1;
    }
    return run_report(argv[1]);
}
