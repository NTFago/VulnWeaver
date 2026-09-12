#!/bin/sh
# Build obfuscated-heap-overflow: compile (gcc, Docker) -> verify obfuscation
# features (nested flattening dispatchers, opaque predicates, position-dependent
# XOR-encoded strings).
#
# Images (override via environment if the local mirror differs):
#   VULNWEAVER_CC_IMAGE default gcc:13-bookworm
#   VULNWEAVER_PACK_IMAGE default vulnweaver-binary-tools:fixed (readelf/objdump)
#
# Obfuscation is hand-written in the source: OLLVM-style flattening in two
# nested state machines, always-true/always-false opaque predicates and
# XOR-encoded string constants with a position-dependent key. Distributed as
# an unpacked ELF; source stays in src/ for registration.
#
# Idempotent: dist/ is wiped and rebuilt from src/ on every run.
# Behaviour assertions cover both registered findings:
#   CWE-122 parse_token (original), CWE-415 free_session.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SAMPLE=$(basename "$SCRIPT_DIR")
CC_IMAGE="${VULNWEAVER_CC_IMAGE:-gcc:13-bookworm}"
VERIFY_IMAGE="${VULNWEAVER_PACK_IMAGE:-vulnweaver-binary-tools:fixed}"

host_mount_path() {
    if command -v cygpath >/dev/null 2>&1; then
        cygpath -m "$1"
    else
        printf '%s' "$1"
    fi
}

docker_sh() {
    MSYS2_ARG_CONV_EXCL='*' docker run --rm --entrypoint sh \
        -v "$(host_mount_path "$SCRIPT_DIR"):/work" -w /work "$1" -c "$2"
}

cd "$SCRIPT_DIR"
rm -rf dist
mkdir -p dist

# 1) x86-64 ELF, non-PIE, no stack protector.
docker_sh "$CC_IMAGE" '
    set -eu
    gcc -O0 -fno-pie -no-pie -fno-stack-protector \
        -o dist/obfuscated-heap-overflow src/token_parser.c
'

# 2) Verify ELF + obfuscation signatures:
#    a) indirect jump through the switch jump tables (nested dispatchers);
#    b) neither banner may appear in `strings` (position-dependent XOR).
docker_sh "$VERIFY_IMAGE" '
    set -eu
    readelf -h dist/obfuscated-heap-overflow | grep -qi "x86-64"
    objdump -d dist/obfuscated-heap-overflow | grep -Eq "jmp[[:space:]]+\\*"
    if strings dist/obfuscated-heap-overflow | grep -Eq "TOKEN-PARSER|SESSION-VAULT"; then
        echo "[verify] banner leaked as plaintext; XOR encoding missing" >&2
        exit 1
    fi
    echo "[verify] obfuscated-heap-overflow: dispatch present, strings encoded"
'

# 3) Behaviour checks inside throwaway containers: a short token decodes and
#    stores fine; an oversized token smashes the heap line buffer and the
#    process aborts or segfaults (CWE-122); --free replays free() on the same
#    lease and aborts deterministically (CWE-415).
docker_sh "$CC_IMAGE" '
    set -eu
    chmod +x dist/obfuscated-heap-overflow
    dist/obfuscated-heap-overflow "tok" | grep -q "TOKEN-PARSER"
    payload=$(printf "A%.0s" $(seq 1 1400))
    set +e
    dist/obfuscated-heap-overflow "$payload" >/dev/null 2>&1
    status=$?
    set -e
    if [ "$status" -lt 128 ]; then
        echo "[verify] expected abort/segfault for oversized token, got exit $status" >&2
        exit 1
    fi
    echo "[verify] CWE-122 heap overflow trigger crashed as expected (exit $status)"
    # CWE-415: --free replays free() on the same lease -> glibc tcache abort.
    set +e
    dist/obfuscated-heap-overflow --free s1 >/dev/null 2>&1
    status=$?
    set -e
    if [ "$status" -ne 134 ]; then
        echo "[verify] expected abort (134) for double free, got exit $status" >&2
        exit 1
    fi
    echo "[verify] CWE-415 double free trigger aborted as expected (exit 134)"
'

# 4) SHA-256 manifest.
docker_sh "$VERIFY_IMAGE" '
    set -eu
    cd dist && sha256sum obfuscated-heap-overflow > SHA256SUMS && cat SHA256SUMS
'

echo "[build] $SAMPLE done"
