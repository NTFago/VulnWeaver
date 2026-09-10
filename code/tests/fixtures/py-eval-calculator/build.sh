#!/bin/sh
# Validate py-eval-calculator: syntax check + benign-path smoke run in Docker.
#
# Image (override via environment if the local mirror differs):
#   VULNWEAVER_PY_IMAGE default python:3.12-slim
#
# No compilation is needed; the "build" validates syntax (py_compile) and the
# normal evaluation path. The injection trigger itself is documented in
# README.md and only ever runs harmless `id`/`echo` payloads.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SAMPLE=$(basename "$SCRIPT_DIR")
PY_IMAGE="${VULNWEAVER_PY_IMAGE:-python:3.12-slim}"

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

docker_sh "$PY_IMAGE" '
    set -eu
    python -m py_compile src/calculator.py
    result=$(python src/calculator.py "2+2")
    echo "$result" | grep -qx "4"
    echo "[verify] calculator.py: syntax OK, benign path returns 4"
'

# Record the validated source digest as the distribution artifact.
docker_sh "$PY_IMAGE" '
    set -eu
    cd src && sha256sum calculator.py > ../dist/SHA256SUMS && cat ../dist/SHA256SUMS
'

echo "[build] $SAMPLE done"
