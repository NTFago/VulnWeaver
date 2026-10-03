"""Deterministic, digest-bound ExecutionBundle assembly for proof runs.

The bundle is the single CAS object a proof sandbox mounts. It carries the
versioned manifest, the generated driver, the read-only original target the
finding is bound to, and the crafted/control inputs — so a sandbox run can
only ever demonstrate behaviour of the exact registered target version
(ADR-036 target binding). Member names are fixed by this module; the
entrypoint re-verifies every digest before it materializes anything.
"""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from typing import cast

from vulnweaver_artifact_store import ArtifactStore, ArtifactStoreError, StoredObject
from vulnweaver_contracts import (
    BundleFileMember,
    ExecutionBundleKind,
    ExecutionBundleManifest,
    SchemaVersion,
    TargetBinding,
    validate_contract,
)

BUNDLE_MANIFEST_NAME = "vulnweaver-execution-bundle.json"
BUNDLE_DRIVER_NAME = "driver.json"
BUNDLE_TARGET_NAME = "target"
BUNDLE_INPUT_PREFIX = "inputs/"
BUNDLE_CONTROL_PREFIX = "controls/"

DEFAULT_MAX_BUNDLE_BYTES = 256 * 1024 * 1024
MAX_INPUTS = 8
MAX_CONTROLS = 8


class ExecutionBundleError(ValueError):
    """Raised when bundle members are missing or the bundle exceeds limits."""


@dataclass(frozen=True, slots=True)
class BundleInput:
    """One in-bundle payload plus the CAS reference it was copied from."""

    content: bytes
    object_ref: str


def _json_bytes(payload: object) -> bytes:
    return json.dumps(payload, ensure_ascii=True, sort_keys=True).encode("utf-8")


def _digest_of(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


def _member(name: str, content: bytes) -> BundleFileMember:
    return cast(
        BundleFileMember,
        {
            "name": name,
            "digest": _digest_of(content),
            "size_bytes": len(content),
        },
    )


def _load_member(store: ArtifactStore, object_ref: str, *, limit: int) -> BundleInput:
    try:
        stored = store.verify(object_ref)
    except ArtifactStoreError as error:
        raise ExecutionBundleError("bundle member is not available in CAS") from error
    if stored.size_bytes > limit:
        raise ExecutionBundleError("bundle member exceeds its size limit")
    buffer = io.BytesIO()
    with store.open(object_ref) as source:
        buffer.write(source.read(limit + 1))
    content = buffer.getvalue()
    if len(content) != stored.size_bytes:
        raise ExecutionBundleError("bundle member size changed while reading")
    actual = _digest_of(content)
    if actual != stored.digest:
        raise ExecutionBundleError("bundle member digest mismatch")
    return BundleInput(content, object_ref)


def _add_tar_bytes(archive: tarfile.TarFile, name: str, content: bytes, mode: int) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(content)
    info.mode = mode
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    archive.addfile(info, io.BytesIO(content))


@dataclass(frozen=True, slots=True)
class ExecutionBundle:
    """A stored bundle plus the manifest describing its members."""

    stored: StoredObject
    manifest: ExecutionBundleManifest


def build_execution_bundle(
    store: ArtifactStore,
    *,
    bundle_id: str,
    finding_id: str,
    driver_ref: str,
    target_binding: TargetBinding,
    target_ref: str,
    input_refs: Sequence[str],
    control_refs: Sequence[str],
    created_at: str,
    max_bytes: int = DEFAULT_MAX_BUNDLE_BYTES,
) -> ExecutionBundle:
    """Assemble the versioned manifest and pack driver/target/inputs into CAS.

    The caller supplies CAS references that were already resolved through the
    repositories (project ownership checks happen before this point); this
    function re-verifies digests so the manifest never lies about content.
    """

    if not input_refs:
        raise ExecutionBundleError("execution bundle requires at least one crafted input")
    if not control_refs:
        raise ExecutionBundleError("execution bundle requires at least one control input")
    if len(input_refs) > MAX_INPUTS or len(control_refs) > MAX_CONTROLS:
        raise ExecutionBundleError("execution bundle input counts exceed limits")
    if max_bytes < 1:
        raise ValueError("bundle size limit must be positive")

    driver = _load_member(store, driver_ref, limit=256 * 1024)
    target = _load_member(store, target_ref, limit=max_bytes)
    if _digest_of(target.content) != target_binding["digest"]:
        raise ExecutionBundleError("target binding digest does not match target member")
    inputs = [_load_member(store, ref, limit=64 * 1024) for ref in input_refs]
    controls = [_load_member(store, ref, limit=64 * 1024) for ref in control_refs]

    manifest = cast(
        ExecutionBundleManifest,
        {
            "schema_version": SchemaVersion.VALUE_1_0_0,
            "bundle_id": bundle_id,
            "finding_id": finding_id,
            "kind": ExecutionBundleKind.PROOF,
            "driver": _member(BUNDLE_DRIVER_NAME, driver.content),
            "target": _member(BUNDLE_TARGET_NAME, target.content),
            "target_binding": target_binding,
            "inputs": [
                _member(f"{BUNDLE_INPUT_PREFIX}{index:04d}", item.content)
                for index, item in enumerate(inputs)
            ],
            "controls": [
                _member(f"{BUNDLE_CONTROL_PREFIX}{index:04d}", item.content)
                for index, item in enumerate(controls)
            ],
            "created_at": created_at,
        },
    )
    validate_contract("ExecutionBundleManifest", manifest)

    members: list[tuple[str, bytes, int]] = [
        (BUNDLE_DRIVER_NAME, driver.content, 0o555),
        (BUNDLE_TARGET_NAME, target.content, 0o444),
    ]
    for index, item in enumerate(inputs):
        members.append((f"{BUNDLE_INPUT_PREFIX}{index:04d}", item.content, 0o444))
    for index, item in enumerate(controls):
        members.append((f"{BUNDLE_CONTROL_PREFIX}{index:04d}", item.content, 0o444))
    manifest_bytes = _json_bytes(manifest)

    estimated = len(manifest_bytes) + sum(len(content) for _, content, _ in members)
    estimated += 512 * (len(members) + 2) + 1024
    if estimated > max_bytes:
        raise ExecutionBundleError("execution bundle exceeds its configured size limit")

    with tempfile.TemporaryFile(mode="w+b") as bundle_file:
        with tarfile.open(fileobj=bundle_file, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            _add_tar_bytes(archive, BUNDLE_MANIFEST_NAME, manifest_bytes, 0o444)
            for name, content, mode in members:
                _add_tar_bytes(archive, name, content, mode)
        bundle_file.seek(0)
        try:
            stored = store.put_stream(bundle_file, max_bytes=max_bytes)
        except ArtifactStoreError as error:
            raise ExecutionBundleError("execution bundle could not be stored") from error
    return ExecutionBundle(stored, manifest)
