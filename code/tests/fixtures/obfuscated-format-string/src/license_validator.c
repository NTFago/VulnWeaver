/*
 * Teaching sample: "closed-source" license validator whose control flow is
 * hand-flattened (OLLVM-style dispatcher/state machine, cf.
 * teaching-samples/ollvm-style-flattened.c) with a two-level nested state
 * machine in the validation path. Registered findings:
 *   - CWE-134 uncontrolled format string in audit_log()      (original finding)
 *   - CWE-287 improper authentication in validate_license()  (weak check made
 *     explicit 2026-09-12: any key not starting with '-' is accepted and
 *     granted a tier, printed as an observable non-security consequence)
 *   - CWE-121 stack buffer overflow in sync_config()         (added 2026-09-12)
 *
 * 来源：本仓库自编教学样本（2026-09-11，分支 demo/test-fixtures；
 * 2026-09-12 分支 demo/enrich-fixtures 丰富为多漏洞样本）。
 * 授权依据：AGENTS.md §6 “无害样本”定义——手写控制流平坦化形状，非
 * 第三方 OLLVM 产物；格式化字符串触发后果限于向本地终端回显栈上数据，
 * 溢出后果限于本进程崩溃；无持久化、无横向移动、无外部网络访问。
 *
 * 触发方式（后果均为本地回显或本进程崩溃，见 build.sh 断言）：
 *   ./obfuscated-format-string "%p %p %p"                            -> CWE-134 本地回显
 *   ./obfuscated-format-string totally-not-a-license                 -> CWE-287 接受并授予 standard 等级
 *   ./obfuscated-format-string --sync-config $(python3 -c "print('A'*300)") -> CWE-121 SIGSEGV
 *
 * 反混淆预期：外层校验状态机 validate_license() 内嵌等级判定的二级子状态机
 * license_tier()，反编译可见两级 for(;;)+switch(state) 分发器。
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define STATE_INIT     0x4Au
#define STATE_NONNULL  0x91u
#define STATE_NONEMPTY 0xB7u
#define STATE_AUDIT    0xD2u
#define STATE_ACCEPT   0xE8u
#define STATE_REJECT   0xC3u

#define TIER_BOOT      0x27u
#define TIER_PROBE     0x5Eu
#define TIER_REPORT    0xB1u
#define TIER_STOP      0xF3u

/* CWE-134: event is emitted as the format string itself. */
static void audit_log(const char *event) {
    printf(event);
    printf("\n");
}

/*
 * 二级子状态机：CWE-287 的可观察后果——仅按首字符授予 license 等级并打印。
 * 任意通过外层弱校验的 key 都会得到一个等级（确定性、可被分析系统发现）。
 */
static const char *license_tier(const char *key) {
    unsigned int state = TIER_BOOT;
    const char *tier = "standard";

    for (;;) {
        switch (state) {
        case TIER_BOOT:
            state = (key[0] == 'P') ? TIER_REPORT : TIER_PROBE;
            break;
        case TIER_PROBE:
            if (key[0] == 'E') {
                tier = "enterprise";
            }
            state = TIER_STOP;
            break;
        case TIER_REPORT:
            tier = "pro";
            state = TIER_STOP;
            break;
        case TIER_STOP:
        default:
            return tier;
        }
    }
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
            /* CWE-287: 唯一的否定条件是首字符 '-'；任意其他 key 都放行
               （原宽松校验，2026-09-12 登记为设计内弱点）。 */
            state = (key[0] != '-') ? STATE_AUDIT : STATE_REJECT;
            break;
        case STATE_AUDIT:
            audit_log(key);
            /* 弱校验的可观察后果：按首字符授予并打印 license 等级。 */
            printf("license tier: %s\n", license_tier(key));
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

static int sync_config(const char *path) {
    char config_path[64];
    /* CWE-121: the path is copied into a fixed 64-byte stack buffer without
       bounds checks; -fno-stack-protector keeps the crash deterministic. */
    strcpy(config_path, path);
    printf("syncing config from %s\n", config_path);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("usage: %s <license-key> | %s --sync-config <path>\n", argv[0], argv[0]);
        return 1;
    }
    if (strcmp(argv[1], "--sync-config") == 0) {
        if (argc < 3) {
            printf("usage: %s --sync-config <path>\n", argv[0]);
            return 1;
        }
        return sync_config(argv[2]);
    }
    if (validate_license(argv[1])) {
        printf("license accepted\n");
        return 0;
    }
    printf("license rejected\n");
    return 2;
}
