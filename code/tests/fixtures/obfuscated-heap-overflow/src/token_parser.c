/*
 * Teaching sample: "closed-source" token parser protected by hand-written
 * control-flow flattening (two nested state machines), opaque predicates and
 * position-dependent XOR-encoded string constants. Registered findings:
 *   - CWE-122 heap buffer overflow in parse_token() (original finding)
 *   - CWE-415 double free in free_session()         (added 2026-09-12)
 *
 * 来源：本仓库自编教学样本（2026-09-11，分支 demo/test-fixtures；
 * 2026-09-12 分支 demo/enrich-fixtures 丰富为多漏洞样本）。
 * 授权依据：AGENTS.md §6 “无害样本”定义——混淆均为手写教学形状；
 * 漏洞触发后果限于本进程被 glibc 检测中止（free 校验）或段错误；
 * 无持久化、无横向移动、无外部网络访问。
 *
 * 触发方式（后果均为本进程崩溃，见 build.sh 断言）：
 *   ./obfuscated-heap-overflow $(python3 -c "print('A'*1400)") -> CWE-122 abort
 *   ./obfuscated-heap-overflow --free s1                       -> CWE-415 abort 134
 *
 * 反混淆预期：
 *   - 外层会话状态机 run_session() 调用内层解析状态机 parse_token()，两级
 *     各自持有 for(;;)+switch(state) 分发器；
 *   - opaque_gate()/opaque_pair() 为恒真不透明谓词（相邻整数乘积恒为偶数），
 *     opaque_false() 为恒假不透明谓词（n*(n-1) 除 3 只余 0 或 2），反向
 *     分支均为不可达诱饵；
 *   - 字符串常量经按位置变化的 XOR 密钥（0x37+i）编码，`strings` 看不到
 *     明文 "TOKEN-PARSER" / "SESSION-VAULT"。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SESSION_INIT   0x5Au
#define SESSION_GATE   0x2Eu
#define SESSION_OPEN   0x71u
#define SESSION_PARSE  0x0Du
#define SESSION_FREE   0x9Bu
#define SESSION_DONE   0x44u

#define PARSE_DECODE   0x63u
#define PARSE_ALLOC    0x1Fu
#define PARSE_COPY     0xAAu
#define PARSE_EMIT     0x38u
#define PARSE_FINISH   0x7Eu

/*
 * 横幅常量经按位置变化的 XOR 密钥编码（decode 时密钥为 0x37+i），
 * 运行时才还原，抵抗静态 strings 枚举；两条横幅使用同一派生方案。
 */
static const unsigned char ENCODED_TOKEN_BANNER[] = {
    0x63, 0x77, 0x72, 0x7F, 0x75, 0x11, 0x6D, 0x7F, 0x6D, 0x13, 0x04, 0x10
};

static const unsigned char ENCODED_SESSION_BANNER[] = {
    0x64, 0x7D, 0x6A, 0x69, 0x72, 0x73, 0x73, 0x13, 0x69, 0x01, 0x14, 0x0E, 0x17
};

static void decode_banner(const unsigned char *encoded, size_t len, char *out) {
    size_t i;
    for (i = 0; i < len; i++) {
        /* 密钥按字节位置变化：out[i] = encoded[i] ^ (0x37 + i)。 */
        out[i] = (char)(encoded[i] ^ (unsigned char)(0x37u + (unsigned char)i));
    }
    out[len] = '\0';
}

/* 恒真不透明谓词一：n*(n-1) 是相邻整数乘积，恒为偶数。 */
static int opaque_gate(int n) {
    return ((n * (n - 1)) % 2) == 0;
}

/* 恒真不透明谓词二：n*(n+1) 同理恒为偶数。 */
static int opaque_pair(int n) {
    return ((n * (n + 1)) % 2) == 0;
}

/* 恒假不透明谓词：n*(n-1) 被 3 整除只余 0 或 2（连续三整数中必有 3 的倍数）。 */
static int opaque_false(int n) {
    return ((n * (n - 1)) % 3) == 1;
}

/*
 * 内层解析状态机：保持原 parse_token 漏洞行为不变（malloc(1200) 行缓冲 +
 * strcpy 无界拷贝，CWE-122），仅把控制流打散进独立分发器。
 */
static int parse_token(const char *token) {
    char banner[16];
    char *line = NULL;
    unsigned int state = PARSE_DECODE;
    int status = 0;

    decode_banner(ENCODED_TOKEN_BANNER, sizeof(ENCODED_TOKEN_BANNER), banner);
    printf("%s\n", banner);

    for (;;) {
        switch (state) {
        case PARSE_DECODE:
            /* 恒真谓词；else 分支是不可达诱饵，抬高静态分析成本。 */
            state = opaque_pair(7) ? PARSE_ALLOC : PARSE_FINISH;
            break;
        case PARSE_ALLOC:
            /* CWE-122 target: 1200 字节超出 tcache 上限，使 free() 走带
               相邻块校验的常规路径，崩溃行为确定。 */
            line = (char *)malloc(1200);
            state = (line != NULL) ? PARSE_COPY : PARSE_FINISH;
            break;
        case PARSE_COPY:
            /* CWE-122: unbounded copy into the fixed 1200-byte heap buffer. */
            strcpy(line, token);
            state = PARSE_EMIT;
            break;
        case PARSE_EMIT:
            printf("token: %s\n", line);
            free(line);
            status = 0;
            state = PARSE_FINISH;
            break;
        case PARSE_FINISH:
        default:
            return status;
        }
    }
}

/*
 * 会话释放路径：CWE-415——同一 lease 指针被 free() 两次，glibc tcache
 * 的重放检测确定性 abort（exit 134）。
 */
static int free_session(const char *session_id) {
    char banner[20];
    char *lease;

    decode_banner(ENCODED_SESSION_BANNER, sizeof(ENCODED_SESSION_BANNER), banner);
    printf("%s\n", banner);
    printf("closing session %s\n", session_id);

    lease = (char *)malloc(64);
    if (lease == NULL) {
        return 1;
    }
    strcpy(lease, "session-lease");
    printf("releasing lease: %s\n", lease);
    free(lease);
    if (opaque_gate(13)) {
        /* 恒真谓词；else 分支是不可达诱饵。 */
        printf("lease returned to pool\n");
    } else {
        return -1;
    }
    if (opaque_false(9)) {
        /* 恒假谓词：诱饵分支，若可达将跳过双重释放。 */
        return 0;
    }
    /* CWE-415: the same lease block is handed to free() a second time. */
    free(lease);
    return 0;
}

typedef struct {
    const char *token;
    int release_mode; /* 1 = --free：只执行会话释放路径 */
} session_request_t;

/* 外层会话状态机：调用内层解析状态机或会话释放路径。 */
static int run_session(const session_request_t *request) {
    unsigned int state = SESSION_INIT;
    int status = 0;

    for (;;) {
        switch (state) {
        case SESSION_INIT:
            state = (request->token != NULL) ? SESSION_GATE : SESSION_DONE;
            break;
        case SESSION_GATE:
            /* 恒真谓词；else 分支是不可达诱饵。 */
            state = opaque_gate(11) ? SESSION_OPEN : SESSION_DONE;
            break;
        case SESSION_OPEN:
            state = request->release_mode ? SESSION_FREE : SESSION_PARSE;
            break;
        case SESSION_FREE:
            status = free_session(request->token);
            state = SESSION_DONE;
            break;
        case SESSION_PARSE:
            status = parse_token(request->token);
            state = SESSION_DONE;
            break;
        case SESSION_DONE:
        default:
            return status;
        }
    }
}

int main(int argc, char **argv) {
    session_request_t request;

    if (argc < 2) {
        printf("usage: %s <token> | %s --free <session-id>\n", argv[0], argv[0]);
        return 1;
    }
    if (strcmp(argv[1], "--free") == 0) {
        if (argc < 3) {
            printf("usage: %s --free <session-id>\n", argv[0]);
            return 1;
        }
        request.token = argv[2];
        request.release_mode = 1;
    } else {
        /* 默认命令：解析给定 token（原始 CWE-122 路径，保持不变）。 */
        request.token = argv[1];
        request.release_mode = 0;
    }
    return run_session(&request);
}
