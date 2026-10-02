#!/bin/sh
# Build obfuscated-format-string: compile (gcc, Docker) -> verify dispatcher shape.
#
# Images (override via environment if the local mirror differs):
#   VULNWEAVER_CC_IMAGE default gcc:13-bookworm
#
# The obfuscation is hand-written flattening in the source (OLLVM-style
# dispatcher/state machine, two nested levels in the validation path); no
# third-party obfuscator is required, so a plain gcc image reproduces the
# artifact. The sample is distributed as an unpacked ELF (closed-source form
# = binary only; source stays in src/ for registration).
#
# Idempotent: dist/ is wiped and rebuilt from src/ on every run.
# Behaviour assertions cover all three registered findings:
#   CWE-134 audit_log (original), CWE-287 validate_license, CWE-121 sync_config.
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
        -o dist/obfuscated-format-string src/license_validator.c
'

# 2) Verify ELF + control-flow-flattening signature: the state-machine
#    dispatch survives as an indirect jump through the switch jump table.
docker_sh "$VERIFY_IMAGE" '
    set -eu
    readelf -h dist/obfuscated-format-string | grep -qi "x86-64"
    objdump -d dist/obfuscated-format-string | grep -Eq "jmp[[:space:]]+\\*"
    echo "[verify] obfuscated-format-string: x86-64 ELF, indirect switch dispatch present"
'

# 3) Behaviour checks inside throwaway containers.
docker_sh "$CC_IMAGE" '
    set -eu
    chmod +x dist/obfuscated-format-string
    # CWE-134 (original): a plain key is accepted, and "%x" specifiers leak
    # stack data into local stdout.
    dist/obfuscated-format-string "LICENSE-1234" | grep -q "license accepted"
    dist/obfuscated-format-string "%x %x %x" | grep -Eq "[0-9a-f]{4,}"
    echo "[verify] CWE-134 format string leak confirmed (stack hex echoed locally)"
    # CWE-287: the weak check admits any key not starting with "-" and grants
    # an observable tier (deterministic second finding).
    dist/obfuscated-format-string "totally-not-a-license" | grep -q "license tier: standard"
    dist/obfuscated-format-string "E-CORP-9" | grep -q "license tier: enterprise"
    echo "[verify] CWE-287 weak validation confirmed (junk key accepted, tier printed)"
    # CWE-121: short config path is fine; oversized path smashes the stack.
    dist/obfuscated-format-string --sync-config etc/app.conf | grep -q "syncing config from etc/app.conf"
    payload=$(printf "A%.0s" $(seq 1 300))
    set +e
    dist/obfuscated-format-string --sync-config "$payload" >/dev/null 2>&1
    status=$?
    set -e
    if [ "$status" -ne 139 ]; then
        echo "[verify] expected SIGSEGV (139) for oversized config path, got exit $status" >&2
        exit 1
    fi
    echo "[verify] CWE-121 stack overflow trigger crashed as expected (exit 139)"
'

# 4) SHA-256 manifest.
docker_sh "$VERIFY_IMAGE" '
    set -eu
    cd dist && sha256sum obfuscated-format-string > SHA256SUMS && cat SHA256SUMS
'

echo "[build] $SAMPLE done"
