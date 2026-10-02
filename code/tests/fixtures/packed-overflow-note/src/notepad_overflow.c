/*
 * Teaching sample: packed "closed-source" note utility holding three
 * deterministic weaknesses behind a small command dispatch layer:
 *   - CWE-120 stack buffer overflow in save_note()      (original finding)
 *   - CWE-122 heap buffer overflow in list_notes()      (added 2026-09-12)
 *   - CWE-476 NULL pointer dereference in delete_note() (added 2026-09-12)
 *
 * 来源：本仓库自编教学样本（2026-09-11，分支 demo/test-fixtures；
 * 2026-09-12 分支 demo/enrich-fixtures 丰富为多漏洞样本）。
 * 授权依据：AGENTS.md §6 “无害样本”定义——仅包含确定性的缓冲区溢出与
 * 空指针解引用模式，无持久化、无横向移动、无外部网络访问；漏洞触发后果
 * 限于本进程崩溃（SIGSEGV / glibc abort），不可用于攻击真实目标。
 *
 * 触发方式（后果均为本进程崩溃，见 build.sh 断言）：
 *   ./packed-overflow-note $(python3 -c "print('A'*128)")      -> CWE-120 SIGSEGV
 *   ./packed-overflow-note --list $(python3 -c "print('A'*400)") -> CWE-122 abort
 *   ./packed-overflow-note --delete 42                          -> CWE-476 SIGSEGV
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    int in_use;
    char title[24];
} note_record_t;

/* 教学用笔记存储：仅登记一条 id 为 "1" 的记录，其余 id 一律查找失败。 */
static note_record_t NOTE_STORE[1] = { { 1, "shopping-list" } };

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

static int list_notes(const char *filter) {
    char *listing;
    /* CWE-122: the filter is copied without bounds into a fixed 1200-byte
       heap block; the size exceeds the tcache maximum, so glibc free() takes
       the checked unsorted-bin path and aborts deterministically on the
       corrupted neighbouring chunk. */
    listing = (char *)malloc(1200);
    if (listing == NULL) {
        return 1;
    }
    strcpy(listing, "notes: (all)");
    strcpy(listing, filter);
    printf("listing: %s\n", listing);
    free(listing);
    return 0;
}

static note_record_t *lookup_record(const char *note_id) {
    /* 教学存储只登记了 id "1"；其余 id 一律查找失败返回 NULL。 */
    if (note_id[0] == '1' && note_id[1] == '\0') {
        return &NOTE_STORE[0];
    }
    return NULL;
}

static int delete_note(const char *note_id) {
    note_record_t *record = lookup_record(note_id);
    /* CWE-476: record is NULL for unknown ids but is dereferenced
       unconditionally; -fno-stack-protector keeps the crash deterministic. */
    if (record->in_use) {
        record->in_use = 0;
        printf("deleted note: %s\n", note_id);
    } else {
        printf("note already inactive: %s\n", note_id);
    }
    return 0;
}

/* 菜单分发层：main 只解析命令字，功能入口由本层进入（main -> dispatch -> 功能函数）。 */
static int dispatch_command(int argc, char **argv) {
    const char *command = argv[1];

    if (strcmp(command, "--list") == 0) {
        if (argc < 3) {
            printf("usage: %s --list <filter>\n", argv[0]);
            return 1;
        }
        return list_notes(argv[2]);
    }
    if (strcmp(command, "--delete") == 0) {
        if (argc < 3) {
            printf("usage: %s --delete <note-id>\n", argv[0]);
            return 1;
        }
        return delete_note(argv[2]);
    }
    /* 默认命令：把参数文本保存为笔记（原始 CWE-120 路径，保持不变）。 */
    return save_note(command);
}

int main(int argc, char **argv) {
    print_banner();
    if (argc < 2) {
        printf("usage: %s <note-text> | %s --list <filter> | %s --delete <note-id>\n",
               argv[0], argv[0], argv[0]);
        return 1;
    }
    return dispatch_command(argc, argv);
}
