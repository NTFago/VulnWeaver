#!/bin/sh
# Validate py-cmd-backup: syntax check + benign-path smoke run in Docker.
#
# Image (override via environment if the local mirror differs):
#   VULNWEAVER_PY_IMAGE default python:3.12-slim
#
# No compilation is needed; the "build" validates syntax (py_compile) and the
# normal backup path. The injection trigger is documented in README.md and
# only ever appends harmless `id`/`echo` payloads (AGENTS.md §6).
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
    python -m py_compile src/backup.py
    result=$(python src/backup.py notes.txt)
    echo "$result" | grep -q "backup-of notes.txt"
    echo "[verify] backup.py: syntax OK, benign path echoes backup-of"
'

# Record the validated source digest as the distribution artifact.
docker_sh "$PY_IMAGE" '
    set -eu
    cd src && sha256sum backup.py > ../dist/SHA256SUMS && cat ../dist/SHA256SUMS
'

echo "[build] $SAMPLE done"
