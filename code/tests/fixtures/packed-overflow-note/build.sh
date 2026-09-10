#!/bin/sh
# Build packed-overflow-note: compile (gcc, Docker) -> UPX pack (Docker) -> verify.
#
# Images (override via environment if the local mirror differs):
#   VULNWEAVER_CC_IMAGE   default gcc:13-bookworm            (compile)
#   VULNWEAVER_PACK_IMAGE default vulnweaver-binary-tools:fixed (upx 4.2.4, readelf)
#
# Idempotent: dist/ is wiped and rebuilt from src/ on every run.
# All execution of the sample happens inside throwaway containers.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SAMPLE=$(basename "$SCRIPT_DIR")
CC_IMAGE="${VULNWEAVER_CC_IMAGE:-gcc:13-bookworm}"
PACK_IMAGE="${VULNWEAVER_PACK_IMAGE:-vulnweaver-binary-tools:fixed}"

# Docker Desktop on Windows needs a Windows-style host path for bind mounts;
# MSYS2_ARG_CONV_EXCL stops Git Bash from mangling the mount argument.
host_mount_path() {
    if command -v cygpath >/dev/null 2>&1; then
        cygpath -m "$1"
    else
        printf '%s' "$1"
    fi
}

docker_sh() {
    # docker_sh <image> <shell-command>
    MSYS2_ARG_CONV_EXCL='*' docker run --rm --entrypoint sh \
        -v "$(host_mount_path "$SCRIPT_DIR"):/work" -w /work "$1" -c "$2"
}

cd "$SCRIPT_DIR"
rm -rf dist
mkdir -p dist

# 1) x86-64 ELF; non-PIE + no stack protector keeps the crash deterministic
#    and the decompiled pseudocode classic for the demo.
docker_sh "$CC_IMAGE" '
    set -eu
    gcc -O0 -fno-pie -no-pie -fno-stack-protector \
        -o dist/packed-overflow-note src/notepad_overflow.c
'

# 2) UPX pack in place (simulated closed-source distribution form).
docker_sh "$PACK_IMAGE" '
    set -eu
    upx -q --best dist/packed-overflow-note
'

# 3) Verify packing artifacts: UPX signature + loadable x86-64 ELF.
docker_sh "$PACK_IMAGE" '
    set -eu
    readelf -h dist/packed-overflow-note | grep -qi "x86-64"
    upx -t dist/packed-overflow-note
    strings dist/packed-overflow-note | grep -q "UPX!"
    echo "[verify] packed-overflow-note: UPX signature present, x86-64 ELF OK"
'

# 4) Behaviour checks inside throwaway containers: benign input exits cleanly,
#    oversized input crashes with SIGSEGV (deterministic CWE-120 trigger).
docker_sh "$CC_IMAGE" '
    set -eu
    chmod +x dist/packed-overflow-note
    dist/packed-overflow-note hello >/dev/null
    payload=$(printf "A%.0s" $(seq 1 200))
    set +e
    dist/packed-overflow-note "$payload" >/dev/null 2>&1
    status=$?
    set -e
    if [ "$status" -lt 128 ]; then
        echo "[verify] expected crash for oversized note, got exit $status" >&2
        exit 1
    fi
    echo "[verify] overflow trigger crashed as expected (exit $status)"
'

# 5) SHA-256 manifest for the distributed artifact.
docker_sh "$PACK_IMAGE" '
    set -eu
    cd dist && sha256sum packed-overflow-note > SHA256SUMS && cat SHA256SUMS
'

echo "[build] $SAMPLE done"
