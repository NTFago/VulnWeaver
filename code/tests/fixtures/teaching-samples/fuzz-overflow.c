/*
 * Teaching sample: deterministic stack buffer overflow (FuzzTool replay).
 * 授权依据：本仓库自编教学样本，仅用于模糊测试链路验收，无恶意功能，
 * 不得用于攻击真实目标。登记于 DEVELOPMENT_STATUS.md 与本文件。
 */
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        return 1;
    }
    char buf[64];
    FILE *f = fopen(argv[1], "rb");
    if (f == NULL) {
        return 1;
    }
    size_t n = fread(buf, 1, sizeof(buf) * 4, f);
    fclose(f);
    if (n >= 4 && memcmp(buf, "VULN", 4) == 0) {
        printf("triggered\n");
    }
    printf("ok\n");
    return 0;
}
