/*
 * Teaching sample: benign control fixture (NO_FINDINGS path).
 *
 * 来源：本仓库自编教学样本（2026-09-11，分支 demo/test-fixtures）。
 * 授权依据：AGENTS.md §6 “无害样本”定义——不含任何已知漏洞模式，
 * 仅对授权文件做有界读取并计算 FNV-1a 摘要；无持久化、无横向移动、
 * 无外部网络访问。
 *
 * 预期分析结论：无发现（NO_FINDINGS）——读取长度受 sizeof 限制、
 * 输出使用常量格式串、无 system/strcpy/eval 等危险原语。
 */
#include <stdint.h>
#include <stdio.h>

#define FNV_OFFSET_BASIS 2166136261u
#define FNV_PRIME 16777619u

static uint32_t fnv1a_file(const char *path) {
    FILE *handle = fopen(path, "rb");
    uint32_t hash = FNV_OFFSET_BASIS;
    unsigned char chunk[256];
    size_t read;

    if (handle == NULL) {
        return 0u;
    }
    while ((read = fread(chunk, 1, sizeof(chunk), handle)) > 0) {
        size_t i;
        for (i = 0; i < read; i++) {
            hash ^= (uint32_t)chunk[i];
            hash *= FNV_PRIME;
        }
    }
    fclose(handle);
    return hash;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file>\n", argv[0]);
        return 1;
    }
    printf("%08x\n", fnv1a_file(argv[1]));
    return 0;
}
