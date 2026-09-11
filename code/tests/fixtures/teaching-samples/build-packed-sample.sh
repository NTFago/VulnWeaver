#!/bin/sh
# Reproducible build for the UPX-packed, control-flow-flattened teaching sample.
#
# Run inside the VulnWeaver Dev Container, which is the project's designated
# build environment (AGENTS.md section 4.1) and the only place that has both a
# compiler and a packer:
#
#     docker compose exec dev sh /workspace/vulnweaver/code/tests/fixtures/teaching-samples/build-packed-sample.sh
#
# Outputs land in ./build/, which is git-ignored.  The binaries are generated
# artefacts and this script is their only source; nothing here is committed.
#
#     packed-flattened.reference   -O0 -g, unpacked, unstripped  -> ground truth
#     packed-flattened.pre-pack    -O0 -s, stripped, not packed  -> pack input
#     packed-flattened.packed      -O0 -s, stripped, UPX-packed  -> sample to analyse
#     packed-flattened.unpacked    result of `upx -d` on the above, for comparison
#
# Only the *unpacked* reference build is executed, and only to self-check the
# REFERENCE_DIGEST constant in the source.  The packed sample itself is never
# executed here; it is only integrity-tested and decompressed by UPX.
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
build_dir="$script_dir/build"
source_file="$script_dir/packed-flattened.c"

for tool in gcc upx readelf cmp; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "error: '$tool' not found." >&2
        if [ "$tool" = "upx" ]; then
            echo "       The Dev Container image must include UPX." >&2
            echo "       Rebuild and recreate it with:" >&2
            echo "         docker compose build dev && docker compose up -d dev" >&2
        fi
        exit 1
    fi
done

mkdir -p "$build_dir"

# UPX refuses to overwrite an existing output, and a stale artefact from an
# earlier revision of the source would be silently compared against below.
# Clear the four known outputs so the script is re-runnable.
rm -f "$build_dir/packed-flattened.reference" \
      "$build_dir/packed-flattened.pre-pack" \
      "$build_dir/packed-flattened.packed" \
      "$build_dir/packed-flattened.unpacked"

# -O0 is load-bearing, not a default.  At -O1 and above GCC folds the dispatcher
# state machine back into the plain loop it represents, which deletes the
# fixture's entire reason for existing.  Do not raise it to "improve" the sample.
gcc -O0 -g -o "$build_dir/packed-flattened.reference" "$source_file"
gcc -O0 -s -o "$build_dir/packed-flattened.pre-pack" "$source_file"

# --- self-check: the embedded ground-truth digest must match the real result ---
if "$build_dir/packed-flattened.reference"; then
    echo "ok: reference build reproduces REFERENCE_DIGEST"
else
    echo "error: reference build does not match REFERENCE_DIGEST in the source." >&2
    echo "       main() returns non-zero when the checksum disagrees.  If the payload" >&2
    echo "       or the algorithm changed, recompute the constant before proceeding." >&2
    exit 1
fi

# --- pack --------------------------------------------------------------------
upx -9 -o "$build_dir/packed-flattened.packed" "$build_dir/packed-flattened.pre-pack"

# --- verify the packing is what the recovery path needs ----------------------
upx -t "$build_dir/packed-flattened.packed"
upx -d -o "$build_dir/packed-flattened.unpacked" "$build_dir/packed-flattened.packed"
if cmp -s "$build_dir/packed-flattened.pre-pack" "$build_dir/packed-flattened.unpacked"; then
    echo "ok: 'upx -d' restores the pre-pack binary byte-for-byte"
else
    echo "error: 'upx -d' did not restore the original bytes" >&2
    exit 1
fi

# --- report what the analyser will actually see ------------------------------
echo
echo "artefacts:"
ls -l "$build_dir" | sed 's/^/  /'

echo
upx_version=$(upx --version 2>/dev/null | sed -n '1s/^upx //p')
sections=$(readelf -S "$build_dir/packed-flattened.packed" 2>&1 | grep -c 'UPX' || true)
if [ "$sections" -gt 0 ]; then
    echo "packed sample exposes $sections UPX-named section(s): header-based"
    echo "detection (_packer_from_sections) will report packer=UPX."
else
    echo "note: the packed sample carries NO section table that names UPX."
    echo "      UPX $upx_version removes the section header table from linux/amd64"
    echo "      output, so _packer_from_sections() sees zero sections and"
    echo "      inspect_binary() reports packed=false, packer=null for this file."
    echo "      Recovery does not depend on it: BinaryAnalysisExecutor calls"
    echo "      UpxAdapter unconditionally (executor.py), so 'upx -t' / 'upx -d'"
    echo "      still unpack the sample and the aggregate is set to"
    echo "      packed=true / packer=UPX from the unpack outcome."
fi
