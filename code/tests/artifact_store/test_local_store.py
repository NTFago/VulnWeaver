from __future__ import annotations

import hashlib
from io import BytesIO
from pathlib import Path
from typing import BinaryIO, cast

import pytest
from vulnweaver_artifact_store import (
    ArtifactIntegrityError,
    ArtifactNotFound,
    ArtifactStoreError,
    ArtifactTooLarge,
    InvalidObjectReference,
    LocalContentAddressedStore,
)


def test_same_content_is_published_once_and_can_be_verified(tmp_path: Path) -> None:
    store = LocalContentAddressedStore(tmp_path, chunk_size=4096)
    content = (b"authorized harmless source\n" * 300) + b"end"
    expected_hash = hashlib.sha256(content).hexdigest()

    first = store.put_stream(BytesIO(content), max_bytes=len(content))
    second = store.put_stream(BytesIO(content), max_bytes=len(content))

    assert first.digest == f"sha256:{expected_hash}"
    assert first.object_ref == f"cas://sha256/{expected_hash}"
    assert first.size_bytes == len(content)
    assert first.created
    assert second == type(second)(
        digest=first.digest,
        object_ref=first.object_ref,
        size_bytes=len(content),
        created=False,
    )
    assert len(list((tmp_path / "objects").rglob(expected_hash))) == 1
    assert list((tmp_path / ".staging").iterdir()) == []

    with store.open(first.object_ref) as stream:
        assert stream.read() == content
    assert store.verify(first.object_ref).digest == first.digest


def test_new_digest_directories_are_synced_from_parent_to_leaf(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = LocalContentAddressedStore(tmp_path)
    synced: list[Path] = []
    monkeypatch.setattr(store, "_sync_directory", synced.append)
    content = b"directory durability"
    digest = hashlib.sha256(content).hexdigest()

    store.put_stream(BytesIO(content), max_bytes=1024)

    objects_root = tmp_path / "objects" / "sha256"
    assert synced == [
        objects_root,
        objects_root / digest[:2],
        objects_root / digest[:2] / digest[2:4],
    ]


def test_size_limit_rejects_content_and_cleans_staging(tmp_path: Path) -> None:
    store = LocalContentAddressedStore(tmp_path, chunk_size=4096)

    with pytest.raises(ArtifactTooLarge) as captured:
        store.put_stream(BytesIO(b"x" * 5000), max_bytes=4096)

    assert captured.value.as_dict()["details"] == {"max_bytes": 4096}
    assert list((tmp_path / ".staging").iterdir()) == []
    assert list((tmp_path / "objects" / "sha256").rglob("*")) == []


@pytest.mark.parametrize(
    "reference",
    [
        "../outside",
        "file:///tmp/sample",
        "cas://sha256/../../outside",
        "cas://sha256/" + "A" * 64,
        "cas://sha256/" + "a" * 63,
    ],
)
def test_object_references_cannot_select_host_paths(
    tmp_path: Path, reference: str
) -> None:
    store = LocalContentAddressedStore(tmp_path)
    with pytest.raises(InvalidObjectReference):
        store.verify(reference)


def test_missing_and_corrupted_objects_are_not_silently_replaced(tmp_path: Path) -> None:
    store = LocalContentAddressedStore(tmp_path, chunk_size=4096)
    content = b"immutable artifact"
    stored = store.put_stream(BytesIO(content), max_bytes=1024)

    with pytest.raises(ArtifactNotFound):
        store.verify("cas://sha256/" + "0" * 64)

    digest = stored.digest.removeprefix("sha256:")
    object_path = next((tmp_path / "objects").rglob(digest))
    object_path.write_bytes(b"tampered")
    with pytest.raises(ArtifactIntegrityError):
        store.verify(stored.object_ref)
    with pytest.raises(ArtifactIntegrityError):
        store.put_stream(BytesIO(content), max_bytes=1024)
    assert object_path.read_bytes() == b"tampered"


def test_source_and_configuration_must_be_bounded_binary_streams(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="chunk_size"):
        LocalContentAddressedStore(tmp_path, chunk_size=1)

    store = LocalContentAddressedStore(tmp_path)
    with pytest.raises(ValueError, match="max_bytes"):
        store.put_stream(BytesIO(), max_bytes=0)
    with pytest.raises(ArtifactIntegrityError, match="yield bytes"):
        store.put_stream(cast(BinaryIO, _TextSource()), max_bytes=10)


def test_store_errors_have_a_service_safe_shape() -> None:
    error = ArtifactStoreError("storage failed", details={"operation": "put"})
    assert error.as_dict() == {
        "code": "artifact_store_error",
        "message": "storage failed",
        "retryable": False,
        "details": {"operation": "put"},
    }


class _TextSource:
    def read(self, _size: int) -> str:
        return "not bytes"
