from __future__ import annotations

import hashlib
import io
import stat
import tarfile
import zipfile
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from vulnweaver_artifact_store import LocalContentAddressedStore
from vulnweaver_contracts import ArtifactVersion, SourceLocation
from vulnweaver_source_analysis import ExcerptLimits, SourceExcerptReader, SourceImportError

from tests.persistence.factories import artifact_version


def archive_bytes(files: dict[str, bytes], *, tar: bool = False) -> bytes:
    output = io.BytesIO()
    if tar:
        with tarfile.open(fileobj=output, mode="w:gz") as archive:
            for name, content in files.items():
                entry = tarfile.TarInfo(name)
                entry.size = len(content)
                archive.addfile(entry, io.BytesIO(content))
    else:
        with zipfile.ZipFile(output, "w") as archive:
            for name, content in files.items():
                archive.writestr(name, content)
    return output.getvalue()


def registered(
    store: LocalContentAddressedStore, content: bytes, *, max_bytes: int = 1024 * 1024
) -> ArtifactVersion:
    stored = store.put_stream(io.BytesIO(content), max_bytes=max_bytes)
    version = artifact_version()
    version["digest"], version["object_ref"] = stored.digest, stored.object_ref
    return version


def location(*, path: str = "src/demo.py", start: int = 2, end: int = 2) -> SourceLocation:
    return cast(
        SourceLocation,
        {
            "artifact_version_id": "artifact-version:t03",
            "path": path,
            "start_line": start,
            "end_line": end,
            "start_column": 1,
            "end_column": 2,
        },
    )


@pytest.mark.parametrize("tar", [False, True])
def test_verified_excerpt_and_cleanup(tmp_path: Path, tar: bool) -> None:
    store = LocalContentAddressedStore(tmp_path / "cas")
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    version = registered(
        store,
        archive_bytes(
            {
                "src/demo.py": b"# source facts\ndef greet():\n    return 'hello'\n",
                "README.md": b"UNRELATED_FILE_MUST_NOT_ENTER_CONTEXT",
            },
            tar=tar,
        ),
    )
    reader = SourceExcerptReader(store, scratch_root=scratch)
    result = reader.read(version, location())
    assert result.text == "# source facts\ndef greet():\n    return 'hello'\n"
    assert result.archive_digest == version["digest"]
    assert result.start_line == 1 and result.end_line == 3
    assert result.truncated is False
    assert list(scratch.iterdir()) == []


def test_large_zip_reads_only_the_requested_source_member(tmp_path: Path) -> None:
    store = LocalContentAddressedStore(tmp_path / "cas")
    content = archive_bytes(
        {
            "assets/generated.bundle": b"x" * (16 * 1024 * 1024 + 1),
            "src/demo.py": b"def greet():\n    return 'hello'\n",
        }
    )
    assert len(content) > 16 * 1024 * 1024
    version = registered(store, content, max_bytes=32 * 1024 * 1024)

    result = SourceExcerptReader(store).read(version, location(start=1, end=2))

    assert result.text == "def greet():\n    return 'hello'\n"


@pytest.mark.parametrize(
    "path",
    [
        "../demo.py",
        "/tmp/demo.py",
        "C:/demo.py",
        "src\\demo.py",
        "src//demo.py",
        ".git/config",
        "src/../demo.py",
    ],
)
def test_host_and_ambiguous_paths_rejected(tmp_path: Path, path: str) -> None:
    store = LocalContentAddressedStore(tmp_path)
    version = registered(store, archive_bytes({"src/demo.py": b"one\ntwo\n"}))
    with pytest.raises((SourceImportError, ValueError)):
        SourceExcerptReader(store).read(version, location(path=path))


@pytest.mark.parametrize(
    "content,code",
    [
        (b"\xff\xfe", "excerpt_non_utf8"),
        (b"a\x00b", "excerpt_binary_content"),
        (b"one\n", "excerpt_line_missing"),
    ],
)
def test_missing_or_non_text_facts_rejected(tmp_path: Path, content: bytes, code: str) -> None:
    store = LocalContentAddressedStore(tmp_path)
    version = registered(store, archive_bytes({"src/demo.py": content}))
    with pytest.raises(SourceImportError) as caught:
        SourceExcerptReader(store).read(version, location())
    assert caught.value.code == code


def test_digest_mismatch_is_not_read_as_source(tmp_path: Path) -> None:
    store = LocalContentAddressedStore(tmp_path)
    version = registered(store, archive_bytes({"src/demo.py": b"one\ntwo\n"}))
    version["digest"] = "sha256:" + "f" * 64
    with pytest.raises(SourceImportError, match="digest"):
        SourceExcerptReader(store).read(version, location())


@pytest.mark.parametrize(
    "limits",
    [
        ExcerptLimits(archive_bytes=10),
        ExcerptLimits(file_bytes=8),
        ExcerptLimits(max_files=1),
        ExcerptLimits(extracted_bytes=16, file_bytes=16),
    ],
)
def test_resource_limits_are_enforced(tmp_path: Path, limits: ExcerptLimits) -> None:
    store = LocalContentAddressedStore(tmp_path)
    version = registered(
        store,
        archive_bytes(
            {
                "src/demo.py": b"12345678\n12345678\n",
                "second.py": b"hello\n",
            }
        ),
    )
    with pytest.raises(SourceImportError):
        SourceExcerptReader(store, limits=limits).read(version, location())


def test_selected_file_budget_reports_the_excerpt_error(tmp_path: Path) -> None:
    store = LocalContentAddressedStore(tmp_path)
    version = registered(store, archive_bytes({"src/demo.py": b"12345678\n12345678\n"}))

    with pytest.raises(SourceImportError) as caught:
        SourceExcerptReader(store, limits=ExcerptLimits(file_bytes=8)).read(version, location())

    assert caught.value.code == "excerpt_file_too_large"


def test_truncated_excerpt_has_explicit_range(tmp_path: Path) -> None:
    store = LocalContentAddressedStore(tmp_path)
    version = registered(store, archive_bytes({"src/demo.py": b"one\ntwo\nthree\nfour\n"}))
    limits = ExcerptLimits(context_lines=0, max_lines=2)
    excerpt = SourceExcerptReader(store, limits=limits).read(version, location(start=1, end=4))
    assert (excerpt.text, excerpt.start_line, excerpt.end_line) == ("one\ntwo\n", 1, 2)
    assert excerpt.truncated
    excerpt = SourceExcerptReader(store, limits=replace(limits, text_bytes=5)).read(
        version, location(start=1, end=2)
    )
    assert excerpt.text == "one\nt" and excerpt.end_line == 2 and excerpt.truncated


def test_archive_symlink_and_traversal_rejected(tmp_path: Path) -> None:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        entry = zipfile.ZipInfo("src/demo.py")
        entry.create_system = 3
        entry.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(entry, "/outside/secret")
    store = LocalContentAddressedStore(tmp_path)
    for payload in [output.getvalue(), archive_bytes({"../escape.py": b"x"})]:
        with pytest.raises(SourceImportError):
            SourceExcerptReader(store).read(registered(store, payload), location())


class _CountingStore:
    """Proxy that counts archive-open calls to expose per-read stream costs."""

    def __init__(self, inner: LocalContentAddressedStore) -> None:
        self._inner = inner
        self.open_calls = 0

    def open(self, object_ref: str):
        self.open_calls += 1
        return self._inner.open(object_ref)

    def verify(self, object_ref: str):
        return self._inner.verify(object_ref)

    def put_stream(self, stream, *, max_bytes: int):
        return self._inner.put_stream(stream, max_bytes=max_bytes)


def _tar_bytes(members: dict[str, bytes]) -> bytes:
    return archive_bytes(members, tar=True)


def test_archive_over_two_thousand_members_reads_members(tmp_path: Path) -> None:
    """Regression: member reads must cover every archive the importer accepts.

    The excerpt reader once passed a 2000-file budget into whole-archive
    metadata validation, so real-world trees like FFmpeg (10k+ files) failed
    every code read and search with ``too_many_files`` — the audit could not
    see a single line of source. The default cap now matches the import
    ceiling, and this archive shape (2500 members) pins the old failure.
    """

    store = LocalContentAddressedStore(tmp_path / "cas")
    members = {
        f"pkg/file{i}.c": f"int f{i}(void) {{ return {i}; }}\n".encode() for i in range(2500)
    }
    members["pkg/anchor.c"] = b"int anchor(void) { return 1; }\n"
    version = registered(store, _tar_bytes(members), max_bytes=4 * 1024 * 1024)

    reader = SourceExcerptReader(store)
    excerpt = reader.read(version, location(path="pkg/anchor.c", start=1, end=1))
    assert excerpt.text == "int anchor(void) { return 1; }\n"

    whole = reader.read_file(version, "pkg/file7.c")
    assert whole.text == "int f7(void) { return 7; }\n"
    assert whole.file_digest == "sha256:" + hashlib.sha256(whole.text.encode()).hexdigest()


def test_second_member_read_does_not_reopen_the_archive(tmp_path: Path) -> None:
    """The warm pass pays the decompression cost once per archive, not per member."""

    store = LocalContentAddressedStore(tmp_path / "cas")
    counting = _CountingStore(store)
    members = {f"src/file{i}.py": f"value = {i}\n".encode() for i in range(300)}
    version = registered(counting, _tar_bytes(members), max_bytes=1024 * 1024)

    reader = SourceExcerptReader(counting)
    first = reader.read_file(version, "src/file1.py")
    opens_after_first = counting.open_calls
    second = reader.read_file(version, "src/file2.py")

    assert first.text == "value = 1\n"
    assert second.text == "value = 2\n"
    assert opens_after_first == 1
    assert counting.open_calls == 1


def test_iter_member_texts_yields_text_and_skips_binary_members(tmp_path: Path) -> None:
    from vulnweaver_source_analysis.archive import ImportLimits, SafeArchiveImporter

    payload = _tar_bytes(
        {
            "src/keep.py": b"keep = True\n",
            "src/also.py": b"also = 'yes'\n",
            "src/binary.bin": b"\xff\xfe\x00\x01",
            "src/broken_text.py": b"broken\x00text",
        }
    )
    importer = SafeArchiveImporter(ImportLimits())
    yielded = dict(importer.iter_member_texts(io.BytesIO(payload)))
    assert yielded == {"src/keep.py": "keep = True\n", "src/also.py": "also = 'yes'\n"}


def test_text_cache_budget_exhaustion_still_reads_members(tmp_path: Path) -> None:
    """Members beyond the cache budget keep taking the strict per-member path."""

    store = LocalContentAddressedStore(tmp_path / "cas")
    counting = _CountingStore(store)
    members = {f"src/file{i}.py": f"value = {i}\n".encode() for i in range(50)}
    version = registered(counting, _tar_bytes(members), max_bytes=1024 * 1024)

    reader = SourceExcerptReader(
        counting, limits=ExcerptLimits(max_cached_text_bytes=1)
    )
    excerpt = reader.read_file(version, "src/file10.py")
    assert excerpt.text == "value = 10\n"
    # Nothing fit the cache, so each member read reopens the archive.
    assert counting.open_calls >= 1


def test_over_budget_member_is_not_cached_but_read(tmp_path: Path) -> None:
    store = LocalContentAddressedStore(tmp_path / "cas")
    big = b"x" * 64
    version = registered(
        store,
        _tar_bytes({"src/big.py": big, "src/small.py": b"small = 1\n"}),
        max_bytes=1024 * 1024,
    )
    reader = SourceExcerptReader(store, limits=ExcerptLimits(file_bytes=32))
    with pytest.raises(SourceImportError, match="budget"):
        reader.read_file(version, "src/big.py")
    assert reader.read_file(version, "src/small.py").text == "small = 1\n"



def test_long_parser_function_fits_one_default_excerpt(tmp_path: Path) -> None:
    """The vobsub_read_header shape: a 186-line function whose sink sits near
    its end. A prologue-only window made the sink invisible to every read
    tool; the default budget must cover such a function in one excerpt."""

    store = LocalContentAddressedStore(tmp_path / "cas")
    body = "".join(f"line {n}\n" for n in range(1, 187)).encode()
    version = registered(store, _tar_bytes({"src/parse.c": body}), max_bytes=1024 * 1024)

    excerpt = SourceExcerptReader(store).read(
        version, location(path="src/parse.c", start=1, end=186)
    )

    assert excerpt.start_line == 1 and excerpt.end_line == 186
    assert not excerpt.truncated
    assert excerpt.text.endswith("line 186\n")


def test_form_feed_does_not_shift_excerpt_lines(tmp_path: Path) -> None:
    """Regression (excerpt/tool line-number double standard): a form feed on
    its own line used to add a phantom line via str.splitlines, shifting every
    excerpt line number against tree-sitter and semgrep/cppcheck diagnostics.
    The review then read the wrong code while read-proof accounting still
    passed. Both sides now count \n only."""

    store = LocalContentAddressedStore(tmp_path / "cas")
    parts = [f"L{n}\n" for n in range(1, 41)]
    parts.insert(4, "\x0c\n")  # form-feed-only line between L4 and L5
    version = registered(
        store, _tar_bytes({"src/parse.c": "".join(parts).encode()}), max_bytes=1024 * 1024
    )

    # \n-only numbering: L20 sits on line 21 (L4 is line 4, the FF is line 5).
    excerpt = SourceExcerptReader(store).read(
        version, location(path="src/parse.c", start=21, end=21)
    )

    assert excerpt.start_line == 11 and excerpt.end_line == 31
    assert "L20\n" in excerpt.text


def test_review_sized_budget_covers_span_wider_than_default(tmp_path: Path) -> None:
    """The review is one shot per finding with no follow-up window shift, so
    its reader must cover a real-world parser span end to end: a 299-line
    finding location under the audit's 220-line window was reviewed with the
    tail cut off and honestly downgraded to unverifiable."""

    store = LocalContentAddressedStore(tmp_path / "cas")
    body = "".join(f"line {n}\n" for n in range(1, 300)).encode()
    version = registered(store, _tar_bytes({"src/parse.c": body}), max_bytes=1024 * 1024)

    reader = SourceExcerptReader(
        store, limits=ExcerptLimits(max_lines=500, text_bytes=128 * 1024)
    )
    excerpt = reader.read(version, location(path="src/parse.c", start=1, end=299))

    assert excerpt.start_line == 1 and excerpt.end_line == 299
    assert not excerpt.truncated
    assert excerpt.text.startswith("line 1\n")
    assert excerpt.text.endswith("line 299\n")
