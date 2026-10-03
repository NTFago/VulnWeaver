#!/bin/sh
# 幂等下载 RealWorld 验收样本，逐文件校验 SHA256SUMS 中锁定的哈希。
# 来源均为官方主机（ffmpeg.org、www.7-zip.org），哈希首次锁定于 2026-10-04。
# 可在任意目录执行：sh download.sh（脚本自行 cd 到所在目录）；需要 curl 与 sha256sum。
set -eu
cd "$(dirname "$0")"
mkdir -p downloads

matches_manifest() {
    f=$1
    [ -f "$f" ] || return 1
    sum=$(sha256sum "$f" | cut -d' ' -f1)
    grep -Fq "$sum  $f" SHA256SUMS
}

while read -r f url; do
    [ -n "${f:-}" ] || continue
    if matches_manifest "$f"; then
        echo "OK(exists) $f"
        continue
    fi
    echo "fetch $f"
    curl -fL --retry 3 --retry-delay 2 --max-time 600 -o "$f.part" "$url"
    mv "$f.part" "$f"
    if ! matches_manifest "$f"; then
        echo "HASH MISMATCH $f (期望见 SHA256SUMS，实际 $(sha256sum "$f" | cut -d' ' -f1))" >&2
        exit 1
    fi
done <<'EOF'
downloads/ffmpeg-8.1.2.tar.xz https://ffmpeg.org/releases/ffmpeg-8.1.2.tar.xz
downloads/ffmpeg-8.1.3.tar.xz https://ffmpeg.org/releases/ffmpeg-8.1.3.tar.xz
downloads/7z2600-linux-x64.tar.xz https://www.7-zip.org/a/7z2600-linux-x64.tar.xz
downloads/7z2601-linux-x64.tar.xz https://www.7-zip.org/a/7z2601-linux-x64.tar.xz
downloads/7z2600-src.7z https://www.7-zip.org/a/7z2600-src.7z
downloads/7z2601-src.7z https://www.7-zip.org/a/7z2601-src.7z
downloads/7z2600-extra.7z https://www.7-zip.org/a/7z2600-extra.7z
downloads/7z2601-extra.7z https://www.7-zip.org/a/7z2601-extra.7z
downloads/7z2600-x64.exe https://www.7-zip.org/a/7z2600-x64.exe
downloads/7z2601-x64.exe https://www.7-zip.org/a/7z2601-x64.exe
EOF

echo "== 全量校验 =="
sha256sum -c SHA256SUMS
