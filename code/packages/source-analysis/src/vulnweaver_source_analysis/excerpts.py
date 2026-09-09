"""Read bounded source facts without executing or trusting archive content."""

from __future__ import annotations

import hashlib
import io
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from vulnweaver_artifact_store import ArtifactStore
from vulnweaver_contracts import ArtifactVersion, SourceLocation, validate_contract

from vulnweaver_source_analysis.archive import ImportLimits, SafeArchiveImporter, SourceImportError


@dataclass(frozen=True, slots=True)
class ExcerptLimits:
    archive_bytes: int = 16 * 1024 * 1024
    extracted_bytes: int = 32 * 1024 * 1024
    file_bytes: int = 1024 * 1024
    max_files: int = 2000
    context_lines: int = 10
    max_lines: int = 80
    text_bytes: int = 16 * 1024

    def __post_init__(self) -> None:
        if not 1 <= self.archive_bytes <= 64 * 1024 * 1024:
            raise ValueError("excerpt archive budget is outside the safe range")
        if not 1 <= self.file_bytes <= self.extracted_bytes <= 128 * 1024 * 1024:
            raise ValueError("excerpt extraction budget is outside the safe range")
        if not 1 <= self.max_files <= 20_000:
            raise ValueError("excerpt file count is outside the safe range")
        if not 0 <= self.context_lines < self.max_lines <= 500:
            raise ValueError("excerpt line budget is outside the safe range")
        if not 1 <= self.text_bytes <= 128 * 1024:
            raise ValueError("excerpt text budget is outside the safe range")


@dataclass(frozen=True, slots=True)
class SourceExcerpt:
    artifact_version_id: str
    archive_ref: str
    archive_digest: str
    path: str
    file_digest: str
    start_line: int
    end_line: int
    text: str
    truncated: bool


class SourceExcerptReader:
    """All filesystem paths are service-owned; requested paths are archive-relative."""

    def __init__(
        self,
        store: ArtifactStore,
        *,
        limits: ExcerptLimits | None = None,
        scratch_root: str | Path | None = None,
    ) -> None:
        self._store = store
        self._limits = limits or ExcerptLimits()
        self._scratch_root = scratch_root
        self._importer = SafeArchiveImporter(
            ImportLimits(
                max_files=self._limits.max_files,
                max_total_bytes=self._limits.extracted_bytes,
                max_file_bytes=self._limits.file_bytes,
            )
        )

    def read(self, version: ArtifactVersion, location: SourceLocation) -> SourceExcerpt:
        validate_contract("SourceLocation", location)
        path = location["path"]
        relative = PurePosixPath(path)
        if (
            not path
            or relative.is_absolute()
            or "\\" in path
            or ":" in path
            or relative.as_posix() != path
            or ".." in relative.parts
            or any(part in {".git", ".gitmodules"} for part in relative.parts)
            or location["artifact_version_id"] != version["id"]
        ):
            raise SourceImportError("excerpt_invalid_location", "Source location is not permitted")
        if location["end_line"] < location["start_line"]:
            raise SourceImportError("excerpt_invalid_location", "Source line range is invalid")

        # Hash and decode the same bounded bytes, avoiding a verify/open race.
        with self._store.open(version["object_ref"]) as source:
            content = source.read(self._limits.archive_bytes + 1)
        if len(content) > self._limits.archive_bytes:
            raise SourceImportError("excerpt_archive_too_large", "Source archive exceeds budget")
        digest = "sha256:" + hashlib.sha256(content).hexdigest()
        if digest != version["digest"] or version["object_ref"] != "cas://sha256/" + digest[7:]:
            raise SourceImportError("excerpt_digest_mismatch", "Source archive digest is invalid")

        with tempfile.TemporaryDirectory(
            prefix="vulnweaver-excerpt-", dir=self._scratch_root
        ) as tmp:
            root = Path(tmp) / "source"
            self._importer.extract(io.BytesIO(content), root)
            selected = root.joinpath(*relative.parts)
            if not selected.is_file() or not selected.resolve().is_relative_to(root.resolve()):
                raise SourceImportError("excerpt_file_missing", "Source file is unavailable")
            with selected.open("rb") as source:
                raw = source.read(self._limits.file_bytes + 1)
        if len(raw) > self._limits.file_bytes:
            raise SourceImportError("excerpt_file_too_large", "Source file exceeds budget")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise SourceImportError("excerpt_non_utf8", "Source file is not UTF-8 text") from error
        if "\x00" in text:
            raise SourceImportError("excerpt_binary_content", "Source file contains binary data")
        lines = text.splitlines(keepends=True)
        anchor = location["start_line"]
        if anchor > len(lines) or location["end_line"] > len(lines):
            raise SourceImportError("excerpt_line_missing", "Source line range is unavailable")
        start = max(1, anchor - self._limits.context_lines)
        desired_end = min(len(lines), location["end_line"] + self._limits.context_lines)
        end = min(desired_end, start + self._limits.max_lines - 1)
        selected_text = "".join(lines[start - 1 : end])
        encoded = selected_text.encode("utf-8")
        truncated = end < desired_end or len(encoded) > self._limits.text_bytes
        if len(encoded) > self._limits.text_bytes:
            selected_text = encoded[: self._limits.text_bytes].decode("utf-8", errors="ignore")
            end = start + len(selected_text.splitlines()) - 1
        if not selected_text:
            raise SourceImportError("excerpt_text_budget", "Source text cannot fit the byte budget")
        return SourceExcerpt(
            artifact_version_id=version["id"],
            archive_ref=version["object_ref"],
            archive_digest=digest,
            path=path,
            file_digest="sha256:" + hashlib.sha256(raw).hexdigest(),
            start_line=start,
            end_line=end,
            text=selected_text,
            truncated=truncated,
        )
