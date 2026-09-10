/*
 * OLLVM-style control-flow-flattening teaching sample.
 *
 * This is a self-authored, non-executable-by-default source fixture that
 * reproduces the dispatcher/state-machine shape emitted by OLLVM's fla pass.
 * It is not an OLLVM-produced binary and contains no network, persistence, or
 * privileged behavior.  It exists solely to regression-test T28 recovery.
 */
#include <stdint.h>

int flattened_score(uint32_t input) {
    uint32_t state = 0x31u;
    int result = 0;

    for (;;) {
        switch (state) {
        case 0x31u:
            state = (input & 1u) ? 0x72u : 0x94u;
            break;
        case 0x72u:
            result = (int)(input + 7u);
            state = 0x5bu;
            break;
        case 0x94u:
            result = (int)(input - 3u);
            state = 0x5bu;
            break;
        case 0x5bu:
            return result;
        default:
            return -1;
        }
    }
}

int main(void) {
    return flattened_score(4u);
}
