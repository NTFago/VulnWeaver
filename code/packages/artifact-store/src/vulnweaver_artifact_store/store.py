"""Local content-addressed storage with immutable publication semantics."""

from __future__ import annotations

import hashlib
import os
import re
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Protocol, cast

from vulnweaver_artifact_store.errors import (
    ArtifactIntegrityError,
    ArtifactNotFound,
    ArtifactStoreError,
    ArtifactStoreIOError,
    ArtifactTooLarge,
    InvalidObjectReference,
)

_OBJECT_REFERENCE = re.compile(r"^cas://sha256/([0-9a-f]{64})$")
_DEFAULT_CHUNK_SIZE = 1024 * 1024


@dataclass(frozen=True, slots=True)
class StoredObject:
    digest: str
    object_ref: str
    size_bytes: int
    created: bool


class ArtifactStore(Protocol):
    def put_stream(self, source: BinaryIO, *, max_bytes: int) -> StoredObject: ...

    @contextmanager
    def open(self, object_ref: str) -> Iterator[BinaryIO]: ...

    def verify(self, object_ref: str) -> StoredObject: ...


class LocalContentAddressedStore:
    """Store bytes below a service-owned root without accepting filesystem paths."""

    def __init__(self, root: str | Path, *, chunk_size: int = _DEFAULT_CHUNK_SIZE) -> None:
        if chunk_size < 4096 or chunk_size > 16 * 1024 * 1024:
            raise ValueError("chunk_size must be between 4 KiB and 16 MiB")
        self._root = Path(root).expanduser().resolve()
        self._objects_root = self._root / "objects" / "sha256"
        self._staging_root = self._root / ".staging"
        self._chunk_size = chunk_size
        try:
            self._objects_root.mkdir(parents=True, exist_ok=True)
            self._staging_root.mkdir(parents=True, exist_ok=True)
        except OSError as error:
            raise _io_error("artifact store could not initialize", error) from error

    def put_stream(self, source: BinaryIO, *, max_bytes: int) -> StoredObject:
        if max_bytes < 1:
            raise ValueError("max_bytes must be positive")

        temporary_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w+b",
                dir=self._staging_root,
                prefix="put-",
                suffix=".tmp",
                delete=False,
            ) as temporary:
                temporary_path = Path(temporary.name)
                digest, size_bytes = self._copy_and_hash(
                    source, cast(BinaryIO, temporary), max_bytes
                )
                temporary.flush()
                os.fsync(temporary.fileno())

            target = self._path_for_digest(digest)
            target.parent.mkdir(parents=True, exist_ok=True)
            self._assert_within_root(target.parent)
            try:
                os.link(temporary_path, target)
                created = True
            except FileExistsError:
                created = False
                self._verify_path(target, digest)
            self._sync_directory(target.parent)
            return StoredObject(
                digest=f"sha256:{digest}",
                object_ref=f"cas://sha256/{digest}",
                size_bytes=size_bytes,
                created=created,
            )
        except ArtifactStoreError:
            raise
        except OSError as error:
            raise _io_error("artifact write failed", error) from error
        finally:
            if temporary_path is not None:
                with suppress(OSError):
                    temporary_path.unlink(missing_ok=True)

    @contextmanager
    def open(self, object_ref: str) -> Iterator[BinaryIO]:
        digest = self._parse_reference(object_ref)
        path = self._existing_path(digest)
        try:
            with path.open("rb") as stream:
                yield stream
        except OSError as error:
            raise _io_error("artifact read failed", error) from error

    def verify(self, object_ref: str) -> StoredObject:
        digest = self._parse_reference(object_ref)
        path = self._existing_path(digest)
        size_bytes = self._verify_path(path, digest)
        return StoredObject(
            digest=f"sha256:{digest}",
            object_ref=object_ref,
            size_bytes=size_bytes,
            created=False,
        )

    def _copy_and_hash(
        self, source: BinaryIO, destination: BinaryIO, max_bytes: int
    ) -> tuple[str, int]:
        hasher = hashlib.sha256()
        size_bytes = 0
        while True:
            chunk = source.read(self._chunk_size)
            if not isinstance(chunk, bytes):
                raise ArtifactIntegrityError("artifact source must yield bytes")
            if not chunk:
                break
            size_bytes += len(chunk)
            if size_bytes > max_bytes:
                raise ArtifactTooLarge(
                    "artifact exceeds its configured size limit",
                    details={"max_bytes": max_bytes},
                )
            hasher.update(chunk)
            destination.write(chunk)
        return hasher.hexdigest(), size_bytes

    def _parse_reference(self, object_ref: str) -> str:
        matched = _OBJECT_REFERENCE.fullmatch(object_ref)
        if matched is None:
            raise InvalidObjectReference(
                "object reference must use canonical cas://sha256 form"
            )
        return matched.group(1)

    def _path_for_digest(self, digest: str) -> Path:
        return self._objects_root / digest[:2] / digest[2:4] / digest

    def _existing_path(self, digest: str) -> Path:
        path = self._path_for_digest(digest)
        if not path.exists():
            raise ArtifactNotFound(
                "artifact object does not exist",
                details={"digest": f"sha256:{digest}"},
            )
        self._assert_within_root(path)
        if path.is_symlink() or not path.is_file():
            raise ArtifactIntegrityError("artifact object is not a regular file")
        return path

    def _verify_path(self, path: Path, expected_digest: str) -> int:
        self._assert_within_root(path)
        if path.is_symlink() or not path.is_file():
            raise ArtifactIntegrityError("artifact object is not a regular file")
        hasher = hashlib.sha256()
        size_bytes = 0
        try:
            with path.open("rb") as stream:
                while chunk := stream.read(self._chunk_size):
                    hasher.update(chunk)
                    size_bytes += len(chunk)
        except OSError as error:
            raise _io_error("artifact verification failed", error) from error
        if hasher.hexdigest() != expected_digest:
            raise ArtifactIntegrityError(
                "artifact content does not match its object reference",
                details={"digest": f"sha256:{expected_digest}"},
            )
        return size_bytes

    def _assert_within_root(self, path: Path) -> None:
        try:
            path.resolve().relative_to(self._root)
        except (OSError, ValueError) as error:
            raise ArtifactIntegrityError("artifact path escapes the configured root") from error

    @staticmethod
    def _sync_directory(path: Path) -> None:
        if os.name == "nt":
            return
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _io_error(message: str, error: OSError) -> ArtifactStoreIOError:
    return ArtifactStoreIOError(message, details={"errno": error.errno})
