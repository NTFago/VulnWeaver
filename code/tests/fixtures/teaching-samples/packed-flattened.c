/*
 * UPX-packed + control-flow-flattened teaching sample (T27/T28 restoration fixture).
 *
 * Self-authored and publicly shareable.  Harmless by construction: it reads no
 * input, performs no I/O, and contains no network, persistence, privilege, or
 * file-system behaviour.  Everything it does is arithmetic over a constant
 * in-memory array.
 *
 * It exists to give the "packed + obfuscated -> restored" chain a sample with a
 * KNOWN answer, so that "did the analysis recover the original semantics?" is a
 * checkable question rather than a judgement call.
 *
 * Two obfuscation layers, one per recovery stage under test:
 *
 *   1. Packing (the shell).  build-packed-sample.sh compresses the compiled ELF
 *      with UPX, so no real code and no symbol is present in the file until it
 *      is unpacked.  Recovery owner: UpxAdapter (`upx -t` / `upx -d`).
 *
 *   2. Control-flow flattening.  flattened_checksum() is written as an
 *      OLLVM-`fla`-style dispatcher state machine rather than as the plain loop
 *      it represents.  Recovery owner: assess_control_flow_flattening() plus
 *      recover_readable_pseudocode().
 *
 * Ground truth and how to check it are in the fixture README.
 *
 * Build: sh build-packed-sample.sh   (inside the Dev Container)
 */
#include <stdint.h>

/* State tags.  OLLVM's `fla` pass numbers its states sequentially, and a dense
 * switch is what the compiler turns into a jump table -- the dispatcher shape
 * the flattening heuristic looks for.  Irregular constants here would compile
 * to a comparison chain instead and the sample would stop representing real
 * `fla` output. */
enum {
    S_ENTRY = 0u,
    S_LOAD = 1u,
    S_MIX = 2u,
    S_STEP = 3u,
    S_EXIT = 4u
};

/* "VulnWeaver-T28" plus a NUL and a high byte, so the payload is not a
 * printable-only run that a strings scan would reunite even while packed. */
static const uint8_t kSamplePayload[] = {
    0x56, 0x75, 0x6c, 0x6e, 0x57, 0x65, 0x61, 0x76,
    0x65, 0x72, 0x2d, 0x54, 0x32, 0x38, 0x00, 0xff
};

/* Finalizer.  A separate function so that a correct restoration also has to
 * recover the one call edge that leaves the dispatcher. */
uint32_t flatten_mix(uint32_t value) {
    return (value << 5) ^ (value >> 27);
}

/*
 * Flattened form of this loop:
 *
 *     uint32_t acc = 0x811c9dc5u;              // FNV-1a 32-bit offset basis
 *     for (uint32_t i = 0; i < length; i++) {
 *         acc ^= (uint32_t)data[i];
 *         acc *= 0x01000193u;                  // FNV-1a 32-bit prime
 *     }
 *     return flatten_mix(acc);
 *
 * The pass/fail criterion for recovery is that the restored pseudocode is
 * recognisable as FNV-1a over `length` bytes followed by a call to
 * flatten_mix().  Anything else means the dispatcher was not recovered.
 */
uint32_t flattened_checksum(const uint8_t *data, uint32_t length) {
    uint32_t state = S_ENTRY;
    uint32_t acc = 0x811c9dc5u;
    uint32_t index = 0;

    for (;;) {
        switch (state) {
        case S_ENTRY:
            index = 0;
            state = S_LOAD;
            break;
        case S_LOAD:
            state = (index < length) ? S_MIX : S_EXIT;
            break;
        case S_MIX:
            acc ^= (uint32_t)data[index];
            acc *= 0x01000193u;
            state = S_STEP;
            break;
        case S_STEP:
            index += 1u;
            state = S_LOAD;
            break;
        case S_EXIT:
            return flatten_mix(acc);
        default:
            return 0u;
        }
    }
}

/* Expected result of flattened_checksum(kSamplePayload, sizeof kSamplePayload).
 * build-packed-sample.sh recomputes it from the reference build and fails the
 * build if this constant has drifted, so it cannot silently go stale. */
#define REFERENCE_DIGEST 0x0770648Eu

int main(void) {
    return (flattened_checksum(kSamplePayload, sizeof kSamplePayload) == REFERENCE_DIGEST)
               ? 0
               : 1;
}
