"""Compile a generated harness inside the fixed AFL++ sandbox image.

The control plane never compiles: it submits a bounded, code-owned
``harness-compile`` profile request and reads back only the structured
diagnostics and the compiled harness artifact the sandbox published.
"""

from __future__ import annotations

import asyncio
import io
import json
import re
import tarfile
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import BinaryIO, Protocol, cast

from vulnweaver_artifact_store import ArtifactStore, ArtifactStoreError, StoredObject
from vulnweaver_contracts import (
    ArtifactKind,
    ResourceBudget,
    SandboxRequest,
    SandboxResult,
    SandboxStatus,
    SchemaVersion,
    ToolIdentity,
    validate_contract,
)
from vulnweaver_tool_runtime import ToolRegistry
from vulnweaver_tool_runtime.errors import ToolRuntimeError

from vulnweaver_fuzzing.profiles import (
    AFL_CASR_TOOL_NAME,
    AFL_CASR_TOOL_VERSION,
    HARNESS_COMPILE_OUTPUT_NAMES,
    HARNESS_COMPILE_PROFILE,
)

HARNESS_SOURCE_NAME = "harness.c"
COMPILE_REPORT_NAME = "compile-report.json"
COMPILED_HARNESS_NAME = "harness.tar"
BUNDLE_MANIFEST_NAME = "vulnweaver-bundle.json"
MAX_HARNESS_SOURCE_BYTES = 65536
MAX_COMPILE_INPUT_BYTES = 512 * 1024 * 1024
MAX_COMPILE_REPORT_BYTES = 64 * 1024
MAX_COMPILED_HARNESS_BYTES = 64 * 1024 * 1024
_FIXTURE_NAME = re.compile(r"^fixtures/[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class SandboxExec(Protocol):
    async def run(
        self, request: SandboxRequest, cancellation: asyncio.Event
    ) -> SandboxResult: ...


class HarnessCompileError(RuntimeError):
    """The harness could not be submitted or its outputs could not be trusted."""


@dataclass(frozen=True, slots=True)
class HarnessCompileOutcome:
    """Structured compiler feedback for one bounded compile attempt."""

    succeeded: bool
    message: str
    compiled_ref: str | None = None
    diagnostics: tuple[str, ...] = ()


def build_harness_bundle(
    store: ArtifactStore,
    source: str,
    *,
    fixtures: Sequence[str] = (),
    max_source_bytes: int = MAX_HARNESS_SOURCE_BYTES,
    max_bytes: int = MAX_COMPILE_INPUT_BYTES,
) -> StoredObject:
    """Write the deterministic harness bundle the compile profile consumes."""

    encoded = source.encode("utf-8")
    if not encoded.strip() or len(encoded) > max_source_bytes:
        raise HarnessCompileError("harness source is empty or exceeds its size budget")
    verified: list[tuple[str, StoredObject]] = []
    for index, fixture_ref in enumerate(fixtures):
        stored = store.verify(fixture_ref)
        verified.append((f"fixtures/{index:04d}.bin", stored))
    estimated = len(encoded) + sum(item.size_bytes for _, item in verified) + 2048
    if estimated > max_bytes:
        raise HarnessCompileError("harness compile bundle exceeds its configured size limit")

    with tempfile.TemporaryFile(mode="w+b") as bundle:
        with tarfile.open(fileobj=bundle, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            _add_bytes(archive, BUNDLE_MANIFEST_NAME, _manifest_bytes(len(verified)))
            _add_bytes(archive, HARNESS_SOURCE_NAME, encoded)
            for name, stored in verified:
                _add_object(archive, store, name, stored)
        bundle.seek(0)
        return store.put_stream(bundle, max_bytes=max_bytes)


class HarnessCompiler:
    """Submit one bounded compile attempt and normalize its structured result."""

    def __init__(
        self,
        store: ArtifactStore,
        registry: ToolRegistry,
        sandbox: SandboxExec,
        *,
        tool: ToolIdentity | None = None,
    ) -> None:
        self._store = store
        self._registry = registry
        self._sandbox = sandbox
        self._tool = tool or ToolIdentity(
            name=AFL_CASR_TOOL_NAME, version=AFL_CASR_TOOL_VERSION, image_digest=None
        )

    async def compile(
        self,
        source: str,
        *,
        request_id: str,
        artifact_version_id: str,
        fixtures: Sequence[str] = (),
        budget: ResourceBudget,
    ) -> HarnessCompileOutcome:
        try:
            spec = self._registry.get(AFL_CASR_TOOL_NAME, AFL_CASR_TOOL_VERSION)
            bundle = build_harness_bundle(self._store, source, fixtures=fixtures)
        except (ArtifactStoreError, HarnessCompileError, ToolRuntimeError, ValueError) as error:
            return HarnessCompileOutcome(False, str(error)[:512])
        request = cast(
            SandboxRequest,
            {
                "schema_version": SchemaVersion.VALUE_1_0_0,
                "id": request_id,
                "tool_name": spec["name"],
                "tool_version": spec["version"],
                "image_digest": spec["image_digest"],
                "artifact_kind": ArtifactKind.DERIVED,
                "input_ref": bundle.object_ref,
                "arguments": {"profile": HARNESS_COMPILE_PROFILE},
                "output_file_names": list(HARNESS_COMPILE_OUTPUT_NAMES),
                "resource_budget": dict(budget),
                "timeout_seconds": budget["timeout_seconds"],
            },
        )
        validate_contract("SandboxRequest", request)
        result = await self._sandbox.run(request, asyncio.Event())
        # The status may arrive as the enum or as its raw value, so compare by value.
        if SandboxStatus(result["status"]) is not SandboxStatus.SUCCEEDED:
            failure = result["failure"]
            message = failure["message"] if failure is not None else "harness compile failed"
            return HarnessCompileOutcome(False, message[:512])
        return self._read_result(result)

    def _read_result(self, result: SandboxResult) -> HarnessCompileOutcome:
        try:
            report = self._read_json(result, COMPILE_REPORT_NAME)
            succeeded = report.get("success") is True
            message = str(report.get("message", ""))[:512]
            raw_diagnostics = report.get("diagnostics")
            diagnostics = (
                tuple(str(item)[:512] for item in cast(list[object], raw_diagnostics))
                if isinstance(raw_diagnostics, list)
                else ()
            )
        except (ArtifactStoreError, HarnessCompileError, ValueError) as error:
            return HarnessCompileOutcome(False, str(error)[:512])
        if not succeeded:
            return HarnessCompileOutcome(False, message, None, diagnostics or (message,))
        try:
            compiled_ref = self._extract_compiled_harness(result)
        except (ArtifactStoreError, HarnessCompileError, tarfile.TarError) as error:
            return HarnessCompileOutcome(False, str(error)[:512])
        if compiled_ref is None:
            return HarnessCompileOutcome(
                False, "compiled harness artifact is missing from the sandbox outputs"
            )
        return HarnessCompileOutcome(True, message, compiled_ref, diagnostics)

    def _extract_compiled_harness(self, result: SandboxResult) -> str | None:
        archive_ref = _single_output_ref(result, COMPILED_HARNESS_NAME)
        if archive_ref is None:
            return None
        stored = self._store.verify(archive_ref)
        if stored.size_bytes > MAX_COMPILE_INPUT_BYTES:
            raise HarnessCompileError("compiled harness archive exceeds its size limit")
        with self._store.open(archive_ref) as source, tarfile.open(
            fileobj=source, mode="r:*"
        ) as archive:
            members = archive.getmembers()
            if len(members) != 1 or members[0].name != "harness" or not members[0].isreg():
                raise HarnessCompileError("compiled harness archive has an unsafe layout")
            member = members[0]
            if member.size <= 0 or member.size > MAX_COMPILED_HARNESS_BYTES:
                raise HarnessCompileError("compiled harness exceeds its size limit")
            extracted = archive.extractfile(member)
            if extracted is None:
                raise HarnessCompileError("compiled harness could not be read")
            with extracted:
                return self._store.put_stream(
                    cast(BinaryIO, extracted), max_bytes=MAX_COMPILED_HARNESS_BYTES
                ).object_ref

    def _read_json(self, result: SandboxResult, name: str) -> Mapping[str, object]:
        matches = [item for item in result["outputs"] if item["path"] == name]
        if len(matches) != 1:
            raise HarnessCompileError(f"sandbox output {name!r} is missing or duplicated")
        output = matches[0]
        stored = self._store.verify(output["object_ref"])
        if stored.digest != output["digest"] or stored.size_bytes != output["size_bytes"]:
            raise HarnessCompileError(f"sandbox output {name!r} has inconsistent CAS metadata")
        if stored.size_bytes > MAX_COMPILE_REPORT_BYTES:
            raise HarnessCompileError(f"sandbox output {name!r} exceeds its parser limit")
        with self._store.open(output["object_ref"]) as source:
            raw = json.loads(source.read().decode("utf-8"))
        if not isinstance(raw, dict):
            raise HarnessCompileError(f"sandbox output {name!r} must be a JSON object")
        return cast(Mapping[str, object], raw)


def _single_output_ref(result: SandboxResult, name: str) -> str | None:
    matches = [item for item in result["outputs"] if item["path"] == name]
    if len(matches) != 1:
        return None
    return matches[0]["object_ref"]


def _manifest_bytes(fixture_count: int) -> bytes:
    return json.dumps(
        {
            "version": "1.0.0",
            "profile": HARNESS_COMPILE_PROFILE,
            "harness": HARNESS_SOURCE_NAME,
            "fixtures": [f"fixtures/{index:04d}.bin" for index in range(fixture_count)],
        },
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def _add_bytes(archive: tarfile.TarFile, name: str, payload: bytes) -> None:
    info = _tar_info(name, len(payload))
    archive.addfile(info, io.BytesIO(payload))


def _add_object(
    archive: tarfile.TarFile, store: ArtifactStore, name: str, stored: StoredObject
) -> None:
    info = _tar_info(name, stored.size_bytes)
    with store.open(stored.object_ref) as source:
        archive.addfile(info, source)


def _tar_info(name: str, size_bytes: int) -> tarfile.TarInfo:
    if (
        name not in {BUNDLE_MANIFEST_NAME, HARNESS_SOURCE_NAME}
        and not _FIXTURE_NAME.fullmatch(name)
    ):
        raise HarnessCompileError("harness bundle contains an unsafe member name")
    info = tarfile.TarInfo(name)
    info.size = size_bytes
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    info.mode = 0o600
    info.uname = ""
    info.gname = ""
    return info
