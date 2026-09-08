from __future__ import annotations

import asyncio
import io
import stat
import tarfile
import time
import zipfile
from pathlib import Path
from typing import BinaryIO, cast

import pytest
from vulnweaver_artifact_store import LocalContentAddressedStore
from vulnweaver_contracts import (
    CapabilityStatus,
    Job,
    JobKind,
    JobStatus,
    SchemaVersion,
    SourceImportResult,
    validate_contract,
)
from vulnweaver_pair import SourcePairImporter
from vulnweaver_persistence import Database, DatabaseSettings, PersistenceInvariantError
from vulnweaver_source_analysis import (
    ArchiveFormat,
    ImportLimits,
    ImportSummary,
    SafeArchiveImporter,
    SourceImportError,
    SourceImportExecutor,
    SourceIndexer,
    SourceIndexerSettings,
)

from tests.persistence.factories import artifact, artifact_version, budget, project, task


def zip_bytes(files: dict[str, bytes]) -> io.BytesIO:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    output.seek(0)
    return output


def executor_job(object_ref: str, *, kind: JobKind | str = JobKind.IMPORT) -> Job:
    return cast(
        Job,
        {
            "schema_version": SchemaVersion.VALUE_1_0_0,
            "id": "job:t12-async",
            "task_id": "task:t12-async",
            "kind": kind,
            "tool": {
                "name": "source-import",
                "version": "1.0.0",
                "image_digest": "sha256:" + "1" * 64,
            },
            "arguments": {"artifact_version_id": "artifact-version:t12-async"},
            "input_refs": [object_ref],
            "status": JobStatus.RUNNING,
            "idempotency_key": "job:t12-async-key",
            "resource_budget": budget(),
            "retry_policy": {
                "max_attempts": 2,
                "backoff_seconds": 1.0,
                "retryable_failure_kinds": [],
            },
            "attempt": 1,
            "lease": None,
            "failure": None,
            "created_at": "2026-09-08T10:00:00Z",
            "updated_at": "2026-09-08T10:00:00Z",
        },
    )


class SlowImporter(SafeArchiveImporter):
    def extract(
        self,
        source: BinaryIO,
        destination: str | Path,
        *,
        filename: str | None = None,
    ) -> ImportSummary:
        del source, filename
        time.sleep(0.1)
        Path(destination).mkdir()
        return ImportSummary(ArchiveFormat.ZIP, 0, 0, 0)


class ImmediateImporter(SafeArchiveImporter):
    def extract(
        self,
        source: BinaryIO,
        destination: str | Path,
        *,
        filename: str | None = None,
    ) -> ImportSummary:
        del source, filename
        Path(destination).mkdir()
        return ImportSummary(ArchiveFormat.ZIP, 0, 0, 0)


class SlowIndexer(SourceIndexer):
    def index(
        self,
        root: str | Path,
        artifact_version_id: str,
        *,
        created_at: str | None = None,
    ) -> SourceImportResult:
        time.sleep(0.1)
        return super().index(root, artifact_version_id, created_at=created_at)


class FailingPairImporter:
    async def import_source_result(self, *_args: object, **_kwargs: object) -> None:
        raise PersistenceInvariantError("PAIR persistence rejected the graph")


def test_safe_zip_import_and_four_language_index(tmp_path: Path) -> None:
    source = zip_bytes(
        {
            "src/main.c": b"int helper(int x){return x;} int main(){return helper(1);}",
            "src/widget.cpp": b"class W { public: int run(int x){ return helper(x); } };",
            "pkg/app.py": b"class App:\n def run(self, x):\n  return helper(x)\n",
            "src/App.java": (
                b"class App { App() {} int run(int x) { return helper(x); } "
                b"int helper(int x) { return x; } }"
            ),
            "CMakeLists.txt": b"project(sample)",
            "pyproject.toml": b"[project]\nname='sample'\n",
            ".git/hooks/post-checkout": b"#!/bin/sh\nexit 99\n",
            ".gitmodules": b"[submodule 'ignored']\n",
        }
    )
    root = tmp_path / "source"
    summary = SafeArchiveImporter().extract(source, root, filename="sample.zip")
    assert summary.files == 6
    assert summary.skipped_git_metadata == 2
    assert not (root / ".git").exists()
    assert not (root / ".gitmodules").exists()

    result = SourceIndexer().index(
        root,
        "artifact-version:t12",
        created_at="2026-09-08T10:00:00Z",
    )
    validate_contract("SourceImportResult", result)
    assert result["capability_profile"]["languages"] == ["c", "cpp", "java", "python"]
    assert result["capability_profile"]["build_systems"] == ["cmake", "python-pyproject"]
    names = {function["qualified_name"] for function in result["functions"]}
    assert {"helper", "main", "W.run", "App.run", "App.helper"} <= names
    assert any(call["callee"].endswith("helper") for call in result["calls"])
    assert all(
        file["path"].startswith(("src/", "pkg/", "CMake", "pyproject")) for file in result["files"]
    )
    available = {
        item["name"]
        for item in result["capability_profile"]["capabilities"]
        if item["status"] is CapabilityStatus.AVAILABLE
    }
    assert "tree_sitter_python" in available


@pytest.mark.parametrize("path", ["../escape.py", "/absolute.py", r"C:\\escape.py"])
def test_zip_path_traversal_and_absolute_paths_are_rejected(tmp_path: Path, path: str) -> None:
    with pytest.raises(SourceImportError) as captured:
        SafeArchiveImporter().extract(zip_bytes({path: b"print('x')"}), tmp_path / "source")
    assert captured.value.code in {"archive_path_traversal", "absolute_archive_path"}
    assert not (tmp_path / "escape.py").exists()


def test_zip_symlink_is_rejected(tmp_path: Path) -> None:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        info = zipfile.ZipInfo("link.py")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(info, "target.py")
    output.seek(0)
    with pytest.raises(SourceImportError, match="symlinks") as captured:
        SafeArchiveImporter().extract(output, tmp_path / "source")
    assert captured.value.code == "special_archive_entry"


@pytest.mark.parametrize(
    "files",
    [
        {"a": b"file", "a/b.py": b"pass"},
        {"a/b.py": b"pass", "a": b"file"},
    ],
)
def test_zip_file_ancestor_collision_is_rejected(tmp_path: Path, files: dict[str, bytes]) -> None:
    with pytest.raises(SourceImportError) as captured:
        SafeArchiveImporter().extract(zip_bytes(files), tmp_path / "source")
    assert captured.value.code == "archive_path_collision"


def test_tar_special_file_is_rejected(tmp_path: Path) -> None:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        info = tarfile.TarInfo("link")
        info.type = tarfile.SYMTYPE
        info.linkname = "outside"
        archive.addfile(info)
    output.seek(0)
    with pytest.raises(SourceImportError) as captured:
        SafeArchiveImporter().extract(output, tmp_path / "source")
    assert captured.value.code == "special_archive_entry"


def test_compression_ratio_and_expanded_size_are_bounded(tmp_path: Path) -> None:
    source = zip_bytes({"huge.txt": b"0" * 100_000})
    importer = SafeArchiveImporter(
        ImportLimits(
            max_files=10,
            max_total_bytes=200_000,
            max_file_bytes=200_000,
            max_compression_ratio=2,
        )
    )
    with pytest.raises(SourceImportError) as captured:
        importer.extract(source, tmp_path / "source")
    assert captured.value.code == "compression_ratio_exceeded"


def test_compressed_tar_ratio_is_bounded(tmp_path: Path) -> None:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        content = b"0" * 100_000
        info = tarfile.TarInfo("huge.txt")
        info.size = len(content)
        archive.addfile(info, io.BytesIO(content))
    output.seek(0)
    importer = SafeArchiveImporter(
        ImportLimits(
            max_files=10,
            max_total_bytes=200_000,
            max_file_bytes=200_000,
            max_compression_ratio=2,
        )
    )
    with pytest.raises(SourceImportError) as captured:
        importer.extract(output, tmp_path / "source")
    assert captured.value.code == "compression_ratio_exceeded"


@pytest.mark.parametrize("path", ["safe:name.py", "CON", "folder/trailing. "])
def test_cross_platform_unsafe_paths_are_rejected(tmp_path: Path, path: str) -> None:
    with pytest.raises(SourceImportError) as captured:
        SafeArchiveImporter().extract(zip_bytes({path: b"pass"}), tmp_path / "source")
    assert captured.value.code == "invalid_archive_path"


def test_indexer_marks_binary_unsupported_and_too_large_files(tmp_path: Path) -> None:
    root = tmp_path / "source"
    root.mkdir()
    (root / "blob.py").write_bytes(b"\x00binary")
    (root / "notes.txt").write_text("notes", encoding="utf-8")
    (root / "large.py").write_text("x = '" + "a" * 2000 + "'", encoding="utf-8")
    result = SourceIndexer().index(root, "artifact-version:t12-default")
    statuses = {item["path"]: item["parse_status"] for item in result["files"]}
    assert statuses == {"blob.py": "binary", "large.py": "indexed", "notes.txt": "unsupported"}

    limited = SourceIndexer(settings=SourceIndexerSettings(max_parse_bytes=1024))
    limited_result = limited.index(root, "artifact-version:t12-limited")
    limited_statuses = {item["path"]: item["parse_status"] for item in limited_result["files"]}
    assert limited_statuses["large.py"] == "too_large"


def test_source_executor_returns_actionable_archive_failure(tmp_path: Path) -> None:
    store = LocalContentAddressedStore(tmp_path / "artifacts")
    payload = b"not an archive"
    stored = store.put_stream(io.BytesIO(payload), max_bytes=len(payload))
    job = cast(
        Job,
        {
            "schema_version": SchemaVersion.VALUE_1_0_0,
            "id": "job:t12-invalid",
            "task_id": "task:t12-invalid",
            "kind": JobKind.IMPORT,
            "tool": {
                "name": "source-import",
                "version": "1.0.0",
                "image_digest": "sha256:" + "1" * 64,
            },
            "arguments": {"artifact_version_id": "artifact-version:t12-invalid"},
            "input_refs": [stored.object_ref],
            "status": JobStatus.RUNNING,
            "idempotency_key": "job:t12-invalid-key",
            "resource_budget": budget(),
            "retry_policy": {
                "max_attempts": 2,
                "backoff_seconds": 1.0,
                "retryable_failure_kinds": [],
            },
            "attempt": 1,
            "lease": None,
            "failure": None,
            "created_at": "2026-09-08T10:00:00Z",
            "updated_at": "2026-09-08T10:00:00Z",
        },
    )
    executor = SourceImportExecutor(cast(Database, object()), store, scratch_root=tmp_path)
    result = asyncio.run(executor.execute(job, asyncio.Event()))
    assert result["status"] is JobStatus.FAILED
    assert result["failure"] is not None
    assert result["failure"]["code"] == "source_import.unsupported_archive"
    assert result["failure"]["kind"].value == "validation"
    assert result["failure"]["retryable"] is False


def test_source_executor_accepts_plain_string_import_kind(tmp_path: Path) -> None:
    cancellation = asyncio.Event()
    cancellation.set()
    executor = SourceImportExecutor(
        cast(Database, object()),
        LocalContentAddressedStore(tmp_path / "artifacts"),
        scratch_root=tmp_path,
    )
    result = asyncio.run(
        executor.execute(executor_job("cas://unused", kind="import"), cancellation)
    )
    assert result["status"] is JobStatus.CANCELLED


@pytest.mark.parametrize("slow_phase", ["extract", "index"])
def test_source_executor_keeps_event_loop_responsive(tmp_path: Path, slow_phase: str) -> None:
    async def scenario() -> None:
        store = LocalContentAddressedStore(tmp_path / "artifacts")
        stored = store.put_stream(io.BytesIO(b"archive"), max_bytes=7)
        cancellation = asyncio.Event()
        asyncio.get_running_loop().call_later(0.02, cancellation.set)
        executor = SourceImportExecutor(
            cast(Database, object()),
            store,
            importer=SlowImporter() if slow_phase == "extract" else ImmediateImporter(),
            indexer=SlowIndexer(),
            scratch_root=tmp_path,
        )
        result = await executor.execute(executor_job(stored.object_ref), cancellation)
        assert result["status"] is JobStatus.CANCELLED

    asyncio.run(scenario())


def test_source_executor_persists_immutable_derived_index(
    persistence_database_url: str, tmp_path: Path
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        store = LocalContentAddressedStore(tmp_path / "artifacts")
        try:
            archive = zip_bytes(
                {
                    "src/main.c": b"int main(){return helper();}",
                    "src/helper.c": b"int helper(){return 1;}\n",
                }
            ).getvalue()
            stored = store.put_stream(io.BytesIO(archive), max_bytes=len(archive))
            async with database.transaction() as repositories:
                await repositories.projects.add(project("project:t12-exec"))
                await repositories.artifacts.add(
                    artifact(
                        "artifact:t12-exec",
                        project_id="project:t12-exec",
                        current_version_id="artifact-version:t12-exec",
                    )
                )
                await repositories.artifacts.add_version(
                    artifact_version(
                        "artifact-version:t12-exec",
                        artifact_id="artifact:t12-exec",
                        digest_character="7",
                    )
                )
                await repositories.tasks.create(
                    task(
                        "task:t12-exec",
                        project_id="project:t12-exec",
                        artifact_version_ids=["artifact-version:t12-exec"],
                        idempotency_key="task:t12-exec-key",
                    )
                )
            job = cast(
                Job,
                {
                    "schema_version": SchemaVersion.VALUE_1_0_0,
                    "id": "job:t12-exec",
                    "task_id": "task:t12-exec",
                    "kind": JobKind.IMPORT,
                    "tool": {
                        "name": "source-import",
                        "version": "1.0.0",
                        "image_digest": "sha256:" + "1" * 64,
                    },
                    "arguments": {"artifact_version_id": "artifact-version:t12-exec"},
                    "input_refs": [stored.object_ref],
                    "status": JobStatus.RUNNING,
                    "idempotency_key": "job:t12-exec-key",
                    "resource_budget": budget(),
                    "retry_policy": {
                        "max_attempts": 2,
                        "backoff_seconds": 1.0,
                        "retryable_failure_kinds": [],
                    },
                    "attempt": 0,
                    "lease": None,
                    "failure": None,
                    "created_at": "2026-09-08T10:00:00Z",
                    "updated_at": "2026-09-08T10:00:00Z",
                },
            )
            executor = SourceImportExecutor(database, store, scratch_root=tmp_path)
            result = await executor.execute(job, asyncio.Event())
            assert result["status"] is JobStatus.SUCCEEDED
            assert len(result["produced_artifact_version_ids"]) == 1
            derived_id = result["produced_artifact_version_ids"][0]
            async with database.transaction() as repositories:
                derived = await repositories.artifacts.get_version(derived_id)
                derived_artifact = await repositories.artifacts.get(derived["artifact_id"])
                assert derived_artifact["kind"].value == "derived"
                assert derived.get("parent_version_id") == "artifact-version:t12-exec"
                produced_by = derived.get("produced_by")
                assert produced_by is not None
                assert produced_by["name"] == "source-import"
                with store.open(derived["object_ref"]) as stream:
                    indexed = stream.read()
                assert b"main" in indexed
                assert b"helper" in indexed

            replay_job = cast(Job, {**job, "updated_at": "2026-09-08T10:05:00Z"})
            replay = await executor.execute(replay_job, asyncio.Event())
            assert replay == result
            objects = [
                path
                for path in (tmp_path / "artifacts" / "objects" / "sha256").rglob("*")
                if path.is_file()
            ]
            assert len(objects) == 2
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_source_executor_returns_terminal_failure_after_index_publish(
    persistence_database_url: str, tmp_path: Path
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        store = LocalContentAddressedStore(tmp_path / "artifacts")
        try:
            archive = zip_bytes({"src/main.c": b"int main(){return 0;}"}).getvalue()
            stored = store.put_stream(io.BytesIO(archive), max_bytes=len(archive))
            async with database.transaction() as repositories:
                await repositories.projects.add(project("project:partial-import"))
                await repositories.artifacts.add(
                    artifact(
                        "artifact:partial-import",
                        project_id="project:partial-import",
                        current_version_id="artifact-version:t12-async",
                    )
                )
                await repositories.artifacts.add_version(
                    artifact_version(
                        "artifact-version:t12-async",
                        artifact_id="artifact:partial-import",
                        digest_character="e",
                    )
                )
                await repositories.tasks.create(
                    task(
                        "task:t12-async",
                        project_id="project:partial-import",
                        artifact_version_ids=["artifact-version:t12-async"],
                    )
                )

            job = executor_job(stored.object_ref)
            executor = SourceImportExecutor(
                database,
                store,
                pair_importer=cast(SourcePairImporter, FailingPairImporter()),
                scratch_root=tmp_path,
            )
            result = await executor.execute(job, asyncio.Event())

            assert result["status"] is JobStatus.FAILED
            assert result["failure"] is not None
            assert result["failure"]["code"] == "source_import.persistence_invariant_violation"
            assert len(result["produced_artifact_version_ids"]) == 1
            async with database.transaction() as repositories:
                published = await repositories.artifacts.get_version(
                    result["produced_artifact_version_ids"][0]
                )
                assert published["parent_version_id"] == "artifact-version:t12-async"
        finally:
            await database.dispose()

    asyncio.run(scenario())
