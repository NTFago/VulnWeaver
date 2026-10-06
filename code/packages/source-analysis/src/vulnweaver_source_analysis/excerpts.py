"""Read bounded source facts without executing or trusting archive content."""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from vulnweaver_artifact_store import ArtifactStore
from vulnweaver_contracts import ArtifactVersion, SourceLocation, validate_contract

from vulnweaver_source_analysis.archive import ImportLimits, SafeArchiveImporter, SourceImportError


@dataclass(frozen=True, slots=True)
class ExcerptLimits:
    archive_bytes: int = 512 * 1024 * 1024
    extracted_bytes: int = 512 * 1024 * 1024
    file_bytes: int = 1024 * 1024
    max_files: int = 20_000
    context_lines: int = 10
    # A real-world parser function dwarfs a course-sized excerpt: the FFmpeg
    # vobsub_read_header spans 186 lines and its out-of-bounds write sits near
    # the end — an 80-line prologue-only window makes the sink invisible to
    # every read tool. 220 lines covers the vast majority of C/C++ functions
    # in one excerpt; anything longer is paged through by the audit's
    # line-anchored read.
    max_lines: int = 220
    text_bytes: int = 32 * 1024
    max_cached_text_bytes: int = 256 * 1024 * 1024

    def __post_init__(self) -> None:
        if not 1 <= self.archive_bytes <= 512 * 1024 * 1024:
            raise ValueError("excerpt archive budget is outside the safe range")
        if not 1 <= self.file_bytes <= self.extracted_bytes <= 512 * 1024 * 1024:
            raise ValueError("excerpt extraction budget is outside the safe range")
        # Member reads validate metadata across the whole archive, so this cap
        # must cover every archive the import path accepts (ImportLimits's
        # max_files): a smaller cap would make every code read of a large but
        # legitimately imported tree fail with too_many_files.
        if not 1 <= self.max_files <= 20_000:
            raise ValueError("excerpt file count is outside the safe range")
        if not 0 <= self.context_lines < self.max_lines <= 500:
            raise ValueError("excerpt line budget is outside the safe range")
        if not 1 <= self.text_bytes <= 128 * 1024:
            raise ValueError("excerpt text budget is outside the safe range")
        if not 1 <= self.max_cached_text_bytes <= 512 * 1024 * 1024:
            raise ValueError("excerpt text cache budget is outside the safe range")


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


@dataclass(frozen=True, slots=True)
class SourceFileText:
    """One whole archive member, decoded for bounded in-memory search."""

    artifact_version_id: str
    path: str
    text: str
    file_digest: str


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
        # Kept for caller compatibility. Excerpts no longer need a scratch directory.
        del scratch_root
        self._verified_archives: dict[tuple[str, str], int] = {}
        self._importer = SafeArchiveImporter(
            ImportLimits(
                max_files=self._limits.max_files,
                max_total_bytes=self._limits.extracted_bytes,
                max_file_bytes=self._limits.extracted_bytes,
            )
        )
        # Warm text cache: one sequential pass per archive materializes every
        # decodable member (within the byte budgets) so a large compressed
        # archive is not re-decompressed for every function read or search hit.
        # Keyed by object_ref, which is content-addressed and immutable.
        self._text_cache: dict[tuple[str, str], str] = {}
        self._warmed: set[str] = set()
        self._warm_lock = threading.Lock()

    def _warm_text_cache(self, version: ArtifactVersion) -> None:
        """Materialize decodable members of one archive into the cache, once.

        Members over ``file_bytes`` or beyond the total cache budget are left
        out on purpose: they keep taking the strict per-member path with its
        exact error codes. The lock matters because audit code search runs the
        reader inside a worker thread while excerpt loads may come from
        ``asyncio.to_thread`` on the same instance.
        """

        object_ref = version["object_ref"]
        if object_ref in self._warmed:
            return
        with self._warm_lock:
            if object_ref in self._warmed:
                return
            cached = 0
            try:
                with self._store.open(object_ref) as source:
                    for path, text in self._importer.iter_member_texts(source):
                        if len(text) > self._limits.file_bytes:
                            continue
                        if cached + len(text) > self._limits.max_cached_text_bytes:
                            break
                        self._text_cache[(object_ref, path)] = text
                        cached += len(text)
            except SourceImportError:
                # A member the warm pass cannot agree on must not poison every
                # read: keep whatever was cached and let the affected members
                # take the strict per-member path with its exact error codes.
                pass
            self._warmed.add(object_ref)

    def _cached_text(self, version: ArtifactVersion, path: str) -> str | None:
        object_ref = version["object_ref"]
        if object_ref not in self._warmed:
            self._warm_text_cache(version)
        return self._text_cache.get((object_ref, path))

    def read(self, version: ArtifactVersion, location: SourceLocation) -> SourceExcerpt:
        validate_contract("SourceLocation", location)
        path = location["path"]
        if location["end_line"] < location["start_line"]:
            raise SourceImportError("excerpt_invalid_location", "Source line range is invalid")
        text, _ = self._read_text_member(version, location["artifact_version_id"], path)
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
            archive_digest=version["digest"],
            path=path,
            file_digest="sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest(),
            start_line=start,
            end_line=end,
            text=selected_text,
            truncated=truncated,
        )

    def read_file(self, version: ArtifactVersion, path: str) -> SourceFileText:
        """Read one whole archive member for bounded search.

        Unlike :meth:`read` this returns the entire file rather than a line
        window, so callers can pattern-match across it. The archive is never
        extracted: only the requested member is decompressed, and the same
        ``file_bytes`` limit that bounds excerpts bounds this read too.
        """

        text, digest = self._read_text_member(version, version["id"], path)
        return SourceFileText(
            artifact_version_id=version["id"],
            path=path,
            text=text,
            file_digest=digest,
        )

    def _read_text_member(
        self, version: ArtifactVersion, artifact_version_id: str, path: str
    ) -> tuple[str, str]:
        """Validate one archive-relative path and return its decoded text and digest."""
        relative = PurePosixPath(path)
        if (
            not path
            or relative.is_absolute()
            or "\\" in path
            or ":" in path
            or relative.as_posix() != path
            or ".." in relative.parts
            or any(part in {".git", ".gitmodules"} for part in relative.parts)
            or artifact_version_id != version["id"]
        ):
            raise SourceImportError("excerpt_invalid_location", "Source location is not permitted")

        digest = version["digest"]
        if version["object_ref"] != "cas://sha256/" + digest.removeprefix("sha256:"):
            raise SourceImportError("excerpt_digest_mismatch", "Source archive digest is invalid")
        archive_key = (version["object_ref"], digest)
        archive_size = self._verified_archives.get(archive_key)
        if archive_size is None:
            stored = self._store.verify(version["object_ref"])
            if stored.digest != digest:
                raise SourceImportError(
                    "excerpt_digest_mismatch", "Source archive digest is invalid"
                )
            archive_size = stored.size_bytes
            self._verified_archives[archive_key] = archive_size
        if archive_size > self._limits.archive_bytes:
            raise SourceImportError("excerpt_archive_too_large", "Source archive exceeds budget")

        cached = self._cached_text(version, relative.as_posix())
        if cached is not None:
            return cached, "sha256:" + hashlib.sha256(cached.encode("utf-8")).hexdigest()

        try:
            with self._store.open(version["object_ref"]) as source:
                raw = self._importer.read_member(
                    source,
                    relative.as_posix(),
                    max_bytes=self._limits.file_bytes,
                )
        except SourceImportError as error:
            if error.code != "file_too_large":
                raise
            raise SourceImportError(
                "excerpt_file_too_large", "Source file exceeds budget", details=error.details
            ) from error
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise SourceImportError("excerpt_non_utf8", "Source file is not UTF-8 text") from error
        if "\x00" in text:
            raise SourceImportError("excerpt_binary_content", "Source file contains binary data")
        return text, "sha256:" + hashlib.sha256(raw).hexdigest()
