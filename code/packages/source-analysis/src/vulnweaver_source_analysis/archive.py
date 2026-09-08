"""Bounded ZIP/TAR extraction without executing repository content."""

from __future__ import annotations

import os
import re
import stat
import tarfile
import zipfile
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Protocol


class ArchiveFormat(StrEnum):
    ZIP = "zip"
    TAR = "tar"


@dataclass(frozen=True, slots=True)
class ImportLimits:
    max_files: int = 20_000
    max_total_bytes: int = 512 * 1024 * 1024
    max_file_bytes: int = 64 * 1024 * 1024
    max_path_length: int = 4096
    max_path_depth: int = 64
    max_compression_ratio: float = 200.0
    copy_chunk_bytes: int = 1024 * 1024

    def __post_init__(self) -> None:
        if self.max_files < 1 or self.max_files > 1_000_000:
            raise ValueError("archive max_files is outside the safe range")
        if self.max_total_bytes < 1 or self.max_file_bytes < 1:
            raise ValueError("archive byte limits must be positive")
        if self.max_file_bytes > self.max_total_bytes:
            raise ValueError("archive per-file limit cannot exceed total limit")
        if self.max_path_length < 16 or self.max_path_depth < 1:
            raise ValueError("archive path limits are too small")
        if self.max_compression_ratio < 1 or self.max_compression_ratio > 10_000:
            raise ValueError("archive compression ratio limit is outside the safe range")
        if self.copy_chunk_bytes < 4096 or self.copy_chunk_bytes > 16 * 1024 * 1024:
            raise ValueError("archive copy chunk must be between 4 KiB and 16 MiB")


@dataclass(frozen=True, slots=True)
class ImportSummary:
    archive_format: ArchiveFormat
    files: int
    total_bytes: int
    skipped_git_metadata: int


class _Readable(Protocol):
    def read(self, size: int = -1, /) -> bytes: ...


class SourceImportError(ValueError):
    def __init__(
        self,
        code: str,
        message: str,
        *,
        details: dict[str, object] | None = None,
    ) -> None:
        self.code = code
        self.message = message
        self.details = details or {}
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class _Entry:
    name: str
    size: int
    compressed_size: int | None
    is_directory: bool
    source: object


_DRIVE_PATH = re.compile(r"^[A-Za-z]:")
_GIT_METADATA = frozenset({".git", ".gitmodules"})
_WINDOWS_DEVICE = re.compile(r"^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?$", re.I)


class SafeArchiveImporter:
    """Extract regular files into a fresh service-owned directory.

    Nested archives are retained as inert files and never recursively expanded, so
    the effective decompression depth is exactly one. Git metadata is ignored and
    no hook, submodule, build tool, package manager, or repository command runs.
    """

    def __init__(self, limits: ImportLimits | None = None) -> None:
        self._limits = limits or ImportLimits()

    def extract(
        self,
        source: BinaryIO,
        destination: str | Path,
        *,
        filename: str | None = None,
    ) -> ImportSummary:
        root = Path(destination)
        try:
            root.mkdir(parents=True, exist_ok=False)
        except FileExistsError as error:
            raise SourceImportError(
                "destination_exists",
                "source import destination must be a new directory",
            ) from error
        archive_bytes = self._stream_size(source)
        source.seek(0)
        if zipfile.is_zipfile(source):
            source.seek(0)
            return self._extract_zip(source, root, archive_bytes)
        source.seek(0)
        try:
            with tarfile.open(fileobj=source, mode="r:*") as archive:
                return self._extract_tar(archive, root, archive_bytes)
        except (tarfile.ReadError, EOFError) as error:
            raise SourceImportError(
                "unsupported_archive",
                "source input must be a valid ZIP or TAR archive",
                details={"filename": filename or "unknown"},
            ) from error

    def _extract_zip(
        self, source: BinaryIO, root: Path, archive_bytes: int
    ) -> ImportSummary:
        try:
            with zipfile.ZipFile(source) as archive:
                entries = [self._zip_entry(info) for info in archive.infolist()]
                selected, file_count, skipped = self._validate_entries(entries)
                self._check_archive_ratio(selected, archive_bytes)
                total = 0
                for entry in selected:
                    if entry.is_directory:
                        self._directory(root, entry.name)
                        continue
                    info = entry.source
                    assert isinstance(info, zipfile.ZipInfo)
                    with archive.open(info, "r") as stream:
                        total += self._write_file(root, entry, stream, total)
                return ImportSummary(ArchiveFormat.ZIP, file_count, total, skipped)
        except (zipfile.BadZipFile, RuntimeError) as error:
            raise SourceImportError("invalid_zip", "ZIP archive could not be read") from error

    def _extract_tar(
        self, archive: tarfile.TarFile, root: Path, archive_bytes: int
    ) -> ImportSummary:
        entries = [self._tar_entry(member) for member in archive.getmembers()]
        selected, file_count, skipped = self._validate_entries(entries)
        self._check_archive_ratio(selected, archive_bytes)
        total = 0
        for entry in selected:
            if entry.is_directory:
                self._directory(root, entry.name)
                continue
            member = entry.source
            assert isinstance(member, tarfile.TarInfo)
            stream = archive.extractfile(member)
            if stream is None:
                raise SourceImportError(
                    "missing_archive_member",
                    "regular TAR member has no readable content",
                    details={"path": entry.name},
                )
            with stream:
                total += self._write_file(root, entry, stream, total)
        return ImportSummary(ArchiveFormat.TAR, file_count, total, skipped)

    @staticmethod
    def _stream_size(source: BinaryIO) -> int:
        source.seek(0, os.SEEK_END)
        size = source.tell()
        if size < 0:
            raise SourceImportError("invalid_archive", "archive size could not be determined")
        return size

    def _check_archive_ratio(self, entries: Iterable[_Entry], archive_bytes: int) -> None:
        expanded_bytes = sum(entry.size for entry in entries if not entry.is_directory)
        ratio = expanded_bytes / max(archive_bytes, 1)
        if expanded_bytes and ratio > self._limits.max_compression_ratio:
            raise SourceImportError(
                "compression_ratio_exceeded",
                "archive compression ratio exceeds the safety limit",
                details={"expanded_bytes": expanded_bytes, "archive_bytes": archive_bytes},
            )

    def _zip_entry(self, info: zipfile.ZipInfo) -> _Entry:
        if info.flag_bits & 0x1:
            raise SourceImportError(
                "encrypted_archive_entry",
                "encrypted ZIP entries are not supported",
                details={"path": info.filename},
            )
        unix_mode = (info.external_attr >> 16) & 0xFFFF
        file_type = stat.S_IFMT(unix_mode)
        if file_type and not (
            stat.S_ISREG(unix_mode) or stat.S_ISDIR(unix_mode)
        ):
            raise SourceImportError(
                "special_archive_entry",
                "ZIP symlinks and special files are forbidden",
                details={"path": info.filename},
            )
        return _Entry(
            info.filename,
            info.file_size,
            info.compress_size,
            info.is_dir(),
            info,
        )

    @staticmethod
    def _tar_entry(member: tarfile.TarInfo) -> _Entry:
        if not member.isfile() and not member.isdir():
            raise SourceImportError(
                "special_archive_entry",
                "TAR links, devices, FIFOs, and special files are forbidden",
                details={"path": member.name},
            )
        return _Entry(member.name, member.size, None, member.isdir(), member)

    def _validate_entries(
        self, entries: Iterable[_Entry]
    ) -> tuple[list[_Entry], int, int]:
        selected: list[_Entry] = []
        seen: set[str] = set()
        files = 0
        total = 0
        skipped = 0
        for entry in entries:
            normalized = self._safe_relative_path(entry.name)
            if not normalized.parts:
                continue
            if normalized.parts[0].casefold() in _GIT_METADATA:
                skipped += 1
                continue
            name = normalized.as_posix()
            collision_key = name.casefold()
            if collision_key in seen:
                raise SourceImportError(
                    "duplicate_archive_path",
                    "archive contains duplicate or case-colliding paths",
                    details={"path": name},
                )
            seen.add(collision_key)
            normalized_entry = _Entry(
                name,
                entry.size,
                entry.compressed_size,
                entry.is_directory,
                entry.source,
            )
            if not entry.is_directory:
                files += 1
                total += entry.size
                self._check_declared_size(normalized_entry, files, total)
            selected.append(normalized_entry)
        return selected, files, skipped

    def _check_declared_size(self, entry: _Entry, files: int, total: int) -> None:
        if files > self._limits.max_files:
            raise SourceImportError("too_many_files", "archive file-count limit exceeded")
        if entry.size < 0 or entry.size > self._limits.max_file_bytes:
            raise SourceImportError(
                "file_too_large",
                "archive member exceeds the per-file size limit",
                details={"path": entry.name, "size": entry.size},
            )
        if total > self._limits.max_total_bytes:
            raise SourceImportError(
                "archive_too_large",
                "archive expanded-size limit exceeded",
                details={"declared_total": total},
            )
        if entry.compressed_size is not None and entry.size:
            compressed = max(entry.compressed_size, 1)
            if entry.size / compressed > self._limits.max_compression_ratio:
                raise SourceImportError(
                    "compression_ratio_exceeded",
                    "archive member compression ratio exceeds the safety limit",
                    details={"path": entry.name},
                )

    def _safe_relative_path(self, value: str) -> PurePosixPath:
        if "\x00" in value:
            raise SourceImportError("invalid_archive_path", "archive path contains NUL")
        normalized = value.replace("\\", "/")
        if normalized.startswith(("/", "//")) or _DRIVE_PATH.match(normalized):
            raise SourceImportError(
                "absolute_archive_path",
                "absolute archive paths are forbidden",
                details={"path": value},
            )
        path = PurePosixPath(normalized)
        parts = tuple(part for part in path.parts if part not in {"", "."})
        if any(part == ".." for part in parts):
            raise SourceImportError(
                "archive_path_traversal",
                "archive path traversal is forbidden",
                details={"path": value},
            )
        if len(parts) > self._limits.max_path_depth:
            raise SourceImportError("archive_path_too_deep", "archive path depth limit exceeded")
        if any(
            ":" in part or part.endswith((" ", ".")) or _WINDOWS_DEVICE.fullmatch(part)
            for part in parts
        ):
            raise SourceImportError(
                "invalid_archive_path",
                "archive path is unsafe on supported filesystems",
                details={"path": value},
            )
        result = PurePosixPath(*parts)
        if len(result.as_posix()) > self._limits.max_path_length:
            raise SourceImportError("archive_path_too_long", "archive path length limit exceeded")
        return result

    def _directory(self, root: Path, name: str) -> None:
        target = root.joinpath(*PurePosixPath(name).parts)
        target.mkdir(parents=True, exist_ok=True)

    def _write_file(
        self,
        root: Path,
        entry: _Entry,
        source: _Readable,
        prior_total: int,
    ) -> int:
        target = root.joinpath(*PurePosixPath(entry.name).parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        written = 0
        try:
            with target.open("xb") as output:
                while chunk := source.read(self._limits.copy_chunk_bytes):
                    written += len(chunk)
                    if written > self._limits.max_file_bytes:
                        raise SourceImportError(
                            "file_too_large",
                            "archive member exceeded the per-file limit while reading",
                            details={"path": entry.name},
                        )
                    if prior_total + written > self._limits.max_total_bytes:
                        raise SourceImportError(
                            "archive_too_large",
                            "archive exceeded the expanded-size limit while reading",
                        )
                    output.write(chunk)
        except FileExistsError as error:
            raise SourceImportError(
                "duplicate_archive_path",
                "archive attempted to overwrite an extracted path",
                details={"path": entry.name},
            ) from error
        if written != entry.size:
            raise SourceImportError(
                "archive_size_mismatch",
                "archive member size changed while reading",
                details={"path": entry.name, "declared": entry.size, "actual": written},
            )
        os.chmod(target, 0o600)
        return written
