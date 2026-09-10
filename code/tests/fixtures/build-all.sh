#!/bin/sh
# Build every Docker-built fixture sample. Idempotent: each sample's
# build.sh wipes and rebuilds its dist/ directory.
set -eu

BASE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

for sample in \
    packed-overflow-note \
    packed-command-injection \
    obfuscated-format-string \
    obfuscated-heap-overflow \
    benign-checksum \
    py-eval-calculator \
    py-cmd-backup
do
    echo "=== [fixtures] building $sample ==="
    sh "$BASE_DIR/$sample/build.sh"
done

echo "=== [fixtures] all samples built ==="
