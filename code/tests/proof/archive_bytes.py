"""Build in-memory tar.gz archives for source-sample test fixtures."""

from __future__ import annotations

import io
import tarfile


def archive_bytes(*members: tuple[str, str | bytes]) -> bytes:
    """One tar.gz holding UTF-8 text members, mirroring the upload path."""

    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, text in members:
            data = text.encode("utf-8") if isinstance(text, str) else text
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()
