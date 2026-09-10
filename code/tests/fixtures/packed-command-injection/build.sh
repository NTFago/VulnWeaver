#!/bin/sh
# Build packed-command-injection: compile (gcc, Docker) -> UPX pack (Docker) -> verify.
#
# Images (override via environment if the local mirror differs):
#   VULNWEAVER_CC_IMAGE   default gcc:13-bookworm            (compile)
#   VULNWEAVER_PACK_IMAGE default vulnweaver-binary-tools:fixed (upx 4.2.4, readelf)
#
# Idempotent: dist/ is wiped and rebuilt from src/ on every run.
# All execution of the sample happens inside throwaway containers; the
# injection check only appends `echo` (harmless, per AGENTS.md §6).
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SAMPLE=$(basename "$SCRIPT_DIR")
CC_IMAGE="${VULNWEAVER_CC_IMAGE:-gcc:13-bookworm}"
PACK_IMAGE="${VULNWEAVER_PACK_IMAGE:-vulnweaver-binary-tools:fixed}"

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
        -o dist/packed-command-injection src/report_helper.c
'

# 2) UPX pack in place.
docker_sh "$PACK_IMAGE" '
    set -eu
    upx -q --best dist/packed-command-injection
'

# 3) Verify packing artifacts.
docker_sh "$PACK_IMAGE" '
    set -eu
    readelf -h dist/packed-command-injection | grep -qi "x86-64"
    upx -t dist/packed-command-injection
    strings dist/packed-command-injection | grep -q "UPX!"
    echo "[verify] packed-command-injection: UPX signature present, x86-64 ELF OK"
'

# 4) Behaviour checks inside throwaway containers: normal run prints the
#    report line; injected `echo` marker proves the CWE-78 sink is reachable.
docker_sh "$CC_IMAGE" '
    set -eu
    chmod +x dist/packed-command-injection
    out=$(dist/packed-command-injection team-a)
    echo "$out" | grep -q "audit-report-for team-a"
    injected=$(dist/packed-command-injection "team-a; echo INJECTED_MARKER_OK")
    echo "$injected" | grep -q "INJECTED_MARKER_OK"
    echo "[verify] command injection path reachable (echo payload only)"
'

# 5) SHA-256 manifest.
docker_sh "$PACK_IMAGE" '
    set -eu
    cd dist && sha256sum packed-command-injection > SHA256SUMS && cat SHA256SUMS
'

echo "[build] $SAMPLE done"
