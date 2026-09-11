#!/bin/sh
# Build benign-checksum: compile (gcc, Docker) -> verify NO_FINDINGS posture.
#
# Images (override via environment if the local mirror differs):
#   VULNWEAVER_CC_IMAGE default gcc:13-bookworm
#   VULNWEAVER_PACK_IMAGE default vulnweaver-binary-tools:fixed (readelf/objdump)
#
# Idempotent: dist/ is wiped and rebuilt from src/ on every run.
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

# 1) x86-64 ELF, benign tool.
docker_sh "$CC_IMAGE" '
    set -eu
    gcc -O2 -o dist/benign-checksum src/checksum_tool.c
'

# 2) Verify ELF + absence of dangerous libc imports (NO_FINDINGS evidence).
docker_sh "$VERIFY_IMAGE" '
    set -eu
    readelf -h dist/benign-checksum | grep -qi "x86-64"
    if objdump -T dist/benign-checksum | grep -Eq "strcpy|system|gets|eval"; then
        echo "[verify] unexpected dangerous import in benign fixture" >&2
        exit 1
    fi
    echo "[verify] benign-checksum: x86-64 ELF, no dangerous imports"
'

# 3) Behaviour check inside a throwaway container: prints an 8-digit FNV-1a
#    digest of an input file and exits 0.
docker_sh "$CC_IMAGE" '
    set -eu
    chmod +x dist/benign-checksum
    digest=$(dist/benign-checksum src/checksum_tool.c)
    echo "$digest" | grep -Eq "^[0-9a-f]{8}$"
    echo "[verify] benign-checksum run OK (digest $digest)"
'

# 4) SHA-256 manifest.
docker_sh "$VERIFY_IMAGE" '
    set -eu
    cd dist && sha256sum benign-checksum > SHA256SUMS && cat SHA256SUMS
'

echo "[build] $SAMPLE done"
