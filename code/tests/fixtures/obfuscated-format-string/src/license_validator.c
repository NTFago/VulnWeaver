/*
 * Teaching sample: "closed-source" license validator whose control flow is
 * hand-flattened (OLLVM-style dispatcher/state machine, cf.
 * teaching-samples/ollvm-style-flattened.c) and that contains an
 * uncontrolled format string (CWE-134).
 *
 * 来源：本仓库自编教学样本（2026-09-11，分支 demo/test-fixtures）。
 * 授权依据：AGENTS.md §6 “无害样本”定义——手写控制流平坦化形状，非
 * 第三方 OLLVM 产物；格式化字符串触发后果限于向本地终端回显栈上数据，
 * 无持久化、无横向移动、无外部网络访问。
 *
 * 预期漏洞：audit_log() 以 printf(event) 直接输出用户输入（CWE-134）。
 * 触发方式：./obfuscated-format-string "%p %p %p"  -> 回显栈数据（本地回显）
 *
 * 反混淆预期：反编译可见 for(;;)+switch(state) 分发器与非常量状态转移。
 */
#include <stdio.h>
#include <string.h>

#define STATE_INIT     0x4Au
#define STATE_NONNULL  0x91u
#define STATE_NONEMPTY 0xB7u
#define STATE_AUDIT    0xD2u
#define STATE_ACCEPT   0xE8u
#define STATE_REJECT   0xC3u

/* CWE-134: event is emitted as the format string itself. */
static void audit_log(const char *event) {
    printf(event);
    printf("\n");
}

static int validate_license(const char *key) {
    unsigned int state = STATE_INIT;
    int verdict = 0;

    /* 手写控制流平坦化：真实逻辑被打散进 switch 状态机。 */
    for (;;) {
        switch (state) {
        case STATE_INIT:
            state = (key != NULL) ? STATE_NONNULL : STATE_REJECT;
            break;
        case STATE_NONNULL:
            state = (strlen(key) > 0u) ? STATE_NONEMPTY : STATE_REJECT;
            break;
        case STATE_NONEMPTY:
            state = (key[0] != '-') ? STATE_AUDIT : STATE_REJECT;
            break;
        case STATE_AUDIT:
            audit_log(key);
            verdict = 1;
            state = STATE_ACCEPT;
            break;
        case STATE_ACCEPT:
            return verdict;
        case STATE_REJECT:
            return 0;
        default:
            return -1;
        }
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("usage: %s <license-key>\n", argv[0]);
        return 1;
    }
    if (validate_license(argv[1])) {
        printf("license accepted\n");
        return 0;
    }
    printf("license rejected\n");
    return 2;
}
