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
# Behaviour assertions cover all three registered findings:
#   CWE-78 run_report (original), CWE-134 export_report, CWE-121 log_event.
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

# 4) Behaviour checks inside throwaway containers.
docker_sh "$CC_IMAGE" '
    set -eu
    chmod +x dist/packed-command-injection
    # CWE-78 (original): normal run prints the report line; injected `echo`
    # marker proves the command injection sink is reachable.
    dist/packed-command-injection team-a | grep -q "audit-report-for team-a"
    dist/packed-command-injection "team-a; echo INJECTED_MARKER_OK" | grep -q "INJECTED_MARKER_OK"
    echo "[verify] CWE-78 command injection path reachable (echo payload only)"
    # CWE-134: a plain name prints; "%p" specifiers echo stack hex locally.
    dist/packed-command-injection --export plain-name | grep -q "export-report: plain-name"
    dist/packed-command-injection --export "%p %p %p" | grep -Eq "0x[0-9a-f]{4,}"
    echo "[verify] CWE-134 format string leak confirmed (stack hex echoed locally)"
    # CWE-121: short log line is fine; oversized message smashes the stack.
    dist/packed-command-injection --log backup-done | grep -q "log: backup-done"
    payload=$(printf "A%.0s" $(seq 1 300))
    set +e
    dist/packed-command-injection --log "$payload" >/dev/null 2>&1
    status=$?
    set -e
    if [ "$status" -ne 139 ]; then
        echo "[verify] expected SIGSEGV (139) for oversized log message, got exit $status" >&2
        exit 1
    fi
    echo "[verify] CWE-121 stack overflow trigger crashed as expected (exit 139)"
'

# 5) SHA-256 manifest.
docker_sh "$PACK_IMAGE" '
    set -eu
    cd dist && sha256sum packed-command-injection > SHA256SUMS && cat SHA256SUMS
'

echo "[build] $SAMPLE done"
