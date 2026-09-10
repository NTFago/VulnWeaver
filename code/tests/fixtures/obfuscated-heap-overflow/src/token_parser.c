/*
 * Teaching sample: "closed-source" token parser protected by hand-written
 * control-flow flattening, opaque predicates and XOR-encoded string
 * constants; contains a heap buffer overflow (CWE-122).
 *
 * 来源：本仓库自编教学样本（2026-09-11，分支 demo/test-fixtures）。
 * 授权依据：AGENTS.md §6 “无害样本”定义——混淆均为手写教学形状；
 * 溢出后果限于本进程被 glibc 检测中止（free 校验）或段错误；无持久化、
 * 无横向移动、无外部网络访问。
 *
 * 预期漏洞：parse_token() 向 malloc(1200) 返回的堆行缓冲 strcpy 无界拷贝
 * （CWE-122；1200 字节超出 tcache 上限，使 glibc free() 走带相邻块校验的
 * 常规路径，崩溃行为确定）。触发方式：./obfuscated-heap-overflow
 * $(python3 -c "print('A'*1400)")  -> glibc abort / SIGSEGV。
 *
 * 反混淆预期：
 *   - for(;;)+switch(state) 分发器；
 *   - opaque_gate() 为恒真不透明谓词（n*(n-1) 恒为偶数），反向分支为诱饵；
 *   - 字符串常量经 XOR 0x37 编码，`strings` 看不到明文 "TOKEN-PARSER"。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define STATE_INIT    0x2Bu
#define STATE_GATE    0x6Eu
#define STATE_DECODE  0x11u
#define STATE_PARSE   0x7Cu
#define STATE_DONE    0x3Fu

/* "TOKEN-PARSER" XOR 0x37 —— 运行时才还原，抵抗静态 strings 枚举。 */
static const unsigned char ENCODED_BANNER[] = {
    0x63, 0x78, 0x7C, 0x72, 0x79, 0x1A, 0x67, 0x76, 0x65, 0x64, 0x72, 0x65
};

static void decode_banner(char *out) {
    size_t i;
    for (i = 0; i < sizeof(ENCODED_BANNER); i++) {
        out[i] = (char)(ENCODED_BANNER[i] ^ 0x37u);
    }
    out[sizeof(ENCODED_BANNER)] = '\0';
}

/* 恒真不透明谓词：n*(n-1) 是相邻整数乘积，恒为偶数。 */
static int opaque_gate(int n) {
    return ((n * (n - 1)) % 2) == 0;
}

static int parse_token(const char *token) {
    char banner[16];
    char *line;

    decode_banner(banner);
    printf("%s\n", banner);

    /* CWE-122: unbounded copy into a fixed 1200-byte heap line buffer. */
    line = (char *)malloc(1200);
    if (line == NULL) {
        return 1;
    }
    strcpy(line, token);
    printf("token: %s\n", line);
    free(line);
    return 0;
}

static int run_pipeline(const char *token) {
    unsigned int state = STATE_INIT;
    int status = 0;

    for (;;) {
        switch (state) {
        case STATE_INIT:
            state = (token != NULL) ? STATE_GATE : STATE_DONE;
            break;
        case STATE_GATE:
            /* 恒真谓词；else 分支是不可达诱饵，抬高静态分析成本。 */
            state = opaque_gate(11) ? STATE_DECODE : STATE_DONE;
            break;
        case STATE_DECODE:
            status = parse_token(token);
            state = STATE_PARSE;
            break;
        case STATE_PARSE:
            state = STATE_DONE;
            break;
        case STATE_DONE:
            return status;
        default:
            return -1;
        }
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("usage: %s <token>\n", argv[0]);
        return 1;
    }
    return run_pipeline(argv[1]);
}
