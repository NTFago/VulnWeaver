"""Bounded request streaming into service-owned temporary files."""

from __future__ import annotations

import asyncio
import hashlib
import os
import tempfile
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass
from pathlib import Path

from fastapi import Request


class UploadTooLarge(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class StagedUpload:
    path: Path
    digest: str
    size_bytes: int
    head: bytes


@asynccontextmanager
async def stage_upload(
    request: Request,
    *,
    max_bytes: int,
    staging_root: Path,
    concurrency: asyncio.Semaphore,
) -> AsyncGenerator[StagedUpload]:
    async with concurrency:
        staging_root.mkdir(parents=True, exist_ok=True)
        path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w+b",
                dir=staging_root,
                prefix="upload-",
                suffix=".tmp",
                delete=False,
            ) as temporary:
                path = Path(temporary.name)
                hasher = hashlib.sha256()
                size_bytes = 0
                head = bytearray()
                async for chunk in request.stream():
                    size_bytes += len(chunk)
                    if size_bytes > max_bytes:
                        raise UploadTooLarge(
                            "uploaded artifact exceeds its configured size limit"
                        )
                    if len(head) < 512:
                        head.extend(chunk[: 512 - len(head)])
                    hasher.update(chunk)
                    await asyncio.to_thread(temporary.write, chunk)
                await asyncio.to_thread(temporary.flush)
                await asyncio.to_thread(os.fsync, temporary.fileno())
                yield StagedUpload(
                    path,
                    f"sha256:{hasher.hexdigest()}",
                    size_bytes,
                    bytes(head),
                )
        finally:
            if path is not None:
                with suppress(OSError):
                    path.unlink(missing_ok=True)


def remove_stale_uploads(staging_root: Path) -> None:
    """Remove only abandoned files created by this upload staging component."""

    staging_root.mkdir(parents=True, exist_ok=True)
    for path in staging_root.glob("upload-*.tmp"):
        with suppress(OSError):
            path.unlink()
