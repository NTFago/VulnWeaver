/*
 * Teaching sample: packed "closed-source" note utility with a classic
 * stack buffer overflow (CWE-120).
 *
 * 来源：本仓库自编教学样本（2026-09-11，分支 demo/test-fixtures）。
 * 授权依据：AGENTS.md §6 “无害样本”定义——仅包含确定性的栈缓冲区溢出
 * 模式，无持久化、无横向移动、无外部网络访问；溢出后果限于本进程崩溃。
 * 触发输入仅为超长参数，不可用于攻击真实目标。
 *
 * 预期漏洞：save_note() 中 strcpy(buf[32], user_input) 无界拷贝（CWE-120）。
 * 触发方式：./packed-overflow-note $(python3 -c "print('A'*128)")  -> SIGSEGV
 */
#include <stdio.h>
#include <string.h>

static void print_banner(void) {
    printf("notepad-overflow-note 1.0 (teaching sample)\n");
}

static int save_note(const char *note) {
    char buffer[32];
    /* CWE-120: unbounded strcpy into a fixed 32-byte stack buffer. */
    strcpy(buffer, note);
    printf("note saved: %s\n", buffer);
    return 0;
}

int main(int argc, char **argv) {
    print_banner();
    if (argc < 2) {
        printf("usage: %s <note-text>\n", argv[0]);
        return 1;
    }
    return save_note(argv[1]);
}
