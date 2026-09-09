from __future__ import annotations

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


def registered(store: LocalContentAddressedStore, content: bytes) -> ArtifactVersion:
    stored = store.put_stream(io.BytesIO(content), max_bytes=1024 * 1024)
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
