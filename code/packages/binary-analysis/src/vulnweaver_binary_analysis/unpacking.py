"""Layered static unpacking: UPX, .NET cleaning, emulated PE unpacking, XOR recovery.

None of these strategies natively executes the sample.  unipacker emulates the
unpacking stub with a Unicorn-based translator -- the same translation-based
class of execution angr already uses -- and every other member is a pure static
transformation.  Native execution of a sample remains reserved for the Sandbox
Runner's dynamic pipeline.
"""

from __future__ import annotations

import asyncio
import hashlib
import importlib.util
import json
import os
import shutil
import struct
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, cast

from vulnweaver_artifact_store import LocalContentAddressedStore, StoredObject
from vulnweaver_contracts import (
    ArtifactKind,
    BinaryArchitecture,
    BinaryFormat,
    BinaryToolRun,
    ResourceBudget,
    SandboxRequest,
    SchemaVersion,
    StaticToolStatus,
)

from vulnweaver_binary_analysis.headers import (
    BinaryInspectionError,
    inspect_binary,
    shannon_entropy,
)
from vulnweaver_binary_analysis.tools import (
    BinaryFactsSandbox,
    BoundedCommandRunner,
    CommandRunner,
    ToolCancelled,
    ToolExecutionError,
    ToolUnavailable,
    UpxAdapter,
    UpxUnpacker,
    bounded_tool_text,
    failed_tool_run,
    unavailable_tool_run,
)
from vulnweaver_binary_analysis.types import BinaryAnalysisLimits, BinaryMetadata

_XOR_MIN_SECTION_BYTES = 64


@dataclass(slots=True)
class UnpackAttempt:
    """One unpacker's bounded result inside a chain round."""

    unpacker: str
    run: BinaryToolRun
    candidate_path: Path | None = None


@dataclass(slots=True)
class UnpackChainOutcome:
    """Aggregate result of the layered unpacking chain."""

    runs: tuple[BinaryToolRun, ...] = ()
    unpacked_path: Path | None = None
    stored: StoredObject | None = None
    method: str | None = None
    methods: tuple[str, ...] = ()
    rounds: int = 0
    packed: bool = True
    final_metadata: BinaryMetadata | None = None


class Unpacker(Protocol):
    """One static unpacking strategy evaluated by the chain."""

    name: str

    def supports(self, metadata: BinaryMetadata) -> bool: ...

    async def unpack(
        self,
        path: Path,
        workdir: Path,
        limits: BinaryAnalysisLimits,
        cancellation: asyncio.Event,
    ) -> UnpackAttempt: ...


class UpxCliUnpacker:
    """Wrap the fixed-argv UPX unpacker as the first chain member."""

    name = "upx"

    def __init__(
        self,
        upx: UpxUnpacker | None = None,
        *,
        executable: str = "upx",
        runner: CommandRunner | None = None,
    ) -> None:
        self._upx = upx or UpxAdapter(executable, runner)

    def supports(self, metadata: BinaryMetadata) -> bool:
        del metadata
        return True

    async def unpack(
        self,
        path: Path,
        workdir: Path,
        limits: BinaryAnalysisLimits,
        cancellation: asyncio.Event,
    ) -> UnpackAttempt:
        destination = workdir / "upx-unpacked.bin"
        outcome = await self._upx.unpack(path, destination, limits, cancellation)
        return UnpackAttempt(
            self.name, outcome.run, outcome.unpacked_path
        )


class De4dotUnpacker:
    """Clean packed or obfuscated .NET assemblies with de4dot under mono."""

    name = "de4dot"

    def __init__(
        self,
        executable: str | None = None,
        *,
        mono_executable: str = "mono",
        runner: CommandRunner | None = None,
    ) -> None:
        self._executable = executable
        self._mono_executable = mono_executable
        self._runner = runner or BoundedCommandRunner()

    def _resolve_executable(self) -> str:
        if self._executable is not None:
            return self._executable
        return os.environ.get("DE4DOT_EXECUTABLE") or "de4dot"

    def supports(self, metadata: BinaryMetadata) -> bool:
        return (
            metadata.format is BinaryFormat.PE
            and metadata.dotnet
            and (metadata.packed or metadata.packer is not None)
        )

    async def unpack(
        self,
        path: Path,
        workdir: Path,
        limits: BinaryAnalysisLimits,
        cancellation: asyncio.Event,
    ) -> UnpackAttempt:
        sample = workdir / "sample.bin"
        await asyncio.to_thread(shutil.copyfile, path, sample)
        try:
            result = await self._runner.run(
                (self._mono_executable, self._resolve_executable(), str(sample)),
                timeout_seconds=limits.command_timeout_seconds,
                max_output_bytes=limits.max_tool_output_bytes,
                cancellation=cancellation,
                cwd=workdir,
            )
        except ToolUnavailable:
            return UnpackAttempt(self.name, unavailable_tool_run(self.name, "executable_not_found"))
        except ToolCancelled:
            raise
        except TimeoutError:
            return UnpackAttempt(self.name, failed_tool_run(self.name, "timeout", None))
        raw = bounded_tool_text(result.stdout + b"\n" + result.stderr, limits.max_raw_output_chars)
        candidate = _find_candidate(workdir, exclude=sample, prefer="-cleaned")
        if result.exit_code != 0 or candidate is None:
            return UnpackAttempt(
                self.name, failed_tool_run(self.name, "unpack_failed", raw, result.exit_code)
            )
        return UnpackAttempt(
            self.name,
            BinaryToolRun(
                tool_name=self.name,
                tool_version=None,
                status=StaticToolStatus.SUCCEEDED,
                exit_code=0,
                reason="unpacked",
                raw_output=raw,
            ),
            candidate,
        )


class UnipackerUnpacker:
    """Emulate a native PE unpacking stub with unipacker and dump the image."""

    name = "unipacker"

    def __init__(
        self, executable: str = "unipacker", *, runner: CommandRunner | None = None
    ) -> None:
        self._executable = executable
        self._runner = runner or BoundedCommandRunner()

    def supports(self, metadata: BinaryMetadata) -> bool:
        return (
            metadata.format is BinaryFormat.PE
            and not metadata.dotnet
            and metadata.architecture in (BinaryArchitecture.X86, BinaryArchitecture.X86_64)
            and (metadata.packed or metadata.packer is not None)
        )

    async def unpack(
        self,
        path: Path,
        workdir: Path,
        limits: BinaryAnalysisLimits,
        cancellation: asyncio.Event,
    ) -> UnpackAttempt:
        sample = workdir / "sample.bin"
        dumps = workdir / "dumps"
        await asyncio.to_thread(shutil.copyfile, path, sample)
        dumps.mkdir()
        try:
            result = await self._runner.run(
                (self._executable, str(sample), "-d", str(dumps)),
                timeout_seconds=limits.command_timeout_seconds,
                max_output_bytes=limits.max_tool_output_bytes,
                cancellation=cancellation,
                cwd=workdir,
            )
        except ToolUnavailable:
            return UnpackAttempt(self.name, unavailable_tool_run(self.name, "executable_not_found"))
        except ToolCancelled:
            raise
        except TimeoutError:
            return UnpackAttempt(self.name, failed_tool_run(self.name, "timeout", None))
        raw = bounded_tool_text(result.stdout + b"\n" + result.stderr, limits.max_raw_output_chars)
        candidate = _find_candidate(dumps) or _find_candidate(workdir, exclude=sample)
        if result.exit_code != 0 or candidate is None:
            return UnpackAttempt(
                self.name, failed_tool_run(self.name, "unpack_failed", raw, result.exit_code)
            )
        return UnpackAttempt(
            self.name,
            BinaryToolRun(
                tool_name=self.name,
                tool_version=None,
                status=StaticToolStatus.SUCCEEDED,
                exit_code=0,
                reason="unpacked",
                raw_output=raw,
            ),
            candidate,
        )


class XorRegionUnpacker:
    """Recover a whole embedded container from a high-entropy packed region.

    A single-byte XOR stub is the common hand-rolled packer: the original image
    sits in one data region and the entry stub decodes it at runtime.  The
    known-plaintext attack is the container magic at the region start, so the
    key falls out of the first four bytes and the region decodes with one table
    translation.
    """

    name = "xor-recovery"

    def __init__(self, *, min_entropy: float = 7.0) -> None:
        self._min_entropy = min_entropy

    def supports(self, metadata: BinaryMetadata) -> bool:
        return metadata.packed and metadata.packer is None

    async def unpack(
        self,
        path: Path,
        workdir: Path,
        limits: BinaryAnalysisLimits,
        cancellation: asyncio.Event,
    ) -> UnpackAttempt:
        del cancellation
        data = await asyncio.to_thread(path.read_bytes)
        if len(data) > limits.max_input_bytes:
            return UnpackAttempt(self.name, failed_tool_run(self.name, "input_too_large", None))
        metadata = await asyncio.to_thread(inspect_binary, path, limits)
        payload = await asyncio.to_thread(
            _xor_recover, data, metadata, self._min_entropy, limits.max_input_bytes
        )
        if payload is None:
            return UnpackAttempt(
                self.name,
                BinaryToolRun(
                    tool_name=self.name,
                    tool_version="1.0.0",
                    status=StaticToolStatus.SUCCEEDED,
                    exit_code=None,
                    reason="no_recoverable_payload",
                    raw_output=None,
                ),
            )
        destination = workdir / "xor-recovered.bin"
        await asyncio.to_thread(destination.write_bytes, payload)
        return UnpackAttempt(
            self.name,
            BinaryToolRun(
                tool_name=self.name,
                tool_version="1.0.0",
                status=StaticToolStatus.SUCCEEDED,
                exit_code=None,
                reason="recovered",
                raw_output=None,
            ),
            destination,
        )


class LiefRebuilder:
    """Best-effort PE repair for candidates whose headers a dumper broke.

    This is the rebuild half of the classic dump-and-reconstruct workflow: when
    a dumped image no longer parses with the strict inspector, re-serialize it
    through LIEF so section and optional headers are well-formed again.  Import
    reconstruction itself is owned by the dumping tool (unipacker rebuilds the
    IAT it resolved during emulation).
    """

    name = "lief"

    def __init__(self, enabled: bool = True) -> None:
        self._enabled = enabled

    @property
    def enabled(self) -> bool:
        return self._enabled and importlib.util.find_spec("lief") is not None

    def repair(self, path: Path, destination: Path) -> bool:
        if not self.enabled:
            return False
        try:
            # LIEF ships no type stubs; going through import_module keeps the
            # untyped surface inside this method instead of infecting callers.
            lief = importlib.import_module("lief")
            parsed = lief.PE.parse(str(path))
            if parsed is None:
                return False
            builder = lief.PE.Builder(parsed)
            builder.build()
            builder.write(str(destination))
        except Exception:
            return False
        return destination.is_file() and destination.stat().st_size > 0


class UnpackerChain:
    """Evaluate unpackers round by round until the image stops improving.

    Each round tries every applicable unpacker in order and switches to the
    first candidate that parses as a different, structurally valid container.
    Rounds repeat while the current image still looks packed, so nested shells
    peel one layer at a time up to `max_rounds`.
    """

    def __init__(
        self,
        unpackers: Sequence[Unpacker],
        *,
        rebuilder: LiefRebuilder | None = None,
        max_rounds: int = 4,
    ) -> None:
        if max_rounds < 1:
            raise ValueError("max_rounds must be positive")
        self._unpackers = tuple(unpackers)
        self._rebuilder = rebuilder
        self._max_rounds = max_rounds

    async def run(
        self,
        path: Path,
        metadata: BinaryMetadata,
        limits: BinaryAnalysisLimits,
        cancellation: asyncio.Event,
    ) -> UnpackChainOutcome:
        runs: list[BinaryToolRun] = []
        methods: list[str] = []
        current_path, current_metadata = path, metadata
        original_digest = await asyncio.to_thread(_file_digest, path)
        rounds = 0
        while rounds < self._max_rounds:
            advanced = False
            for unpacker in self._unpackers:
                if not unpacker.supports(current_metadata):
                    continue
                if cancellation.is_set():
                    break
                workdir = Path(
                    tempfile.mkdtemp(prefix=f"vulnweaver-unpack-{unpacker.name}-", dir=path.parent)
                )
                try:
                    attempt = await unpacker.unpack(current_path, workdir, limits, cancellation)
                except ToolCancelled:
                    raise
                except (OSError, TimeoutError, RuntimeError, ValueError) as error:
                    runs.append(
                        failed_tool_run(unpacker.name, "unpacker_crashed", str(error)[:200])
                    )
                    continue
                runs.append(attempt.run)
                if attempt.candidate_path is None:
                    continue
                accepted = await self._accept(
                    attempt.candidate_path, original_digest, limits
                )
                if accepted is None:
                    continue
                current_path, current_metadata = accepted
                methods.append(attempt.unpacker)
                advanced = True
                break
            if cancellation.is_set() or not advanced:
                break
            if not current_metadata.packed:
                break
            rounds += 1
        unpacked = bool(methods)
        return UnpackChainOutcome(
            runs=tuple(runs),
            unpacked_path=current_path if unpacked else None,
            method=methods[-1] if methods else None,
            methods=tuple(methods),
            rounds=rounds,
            packed=current_metadata.packed if unpacked else metadata.packed,
            final_metadata=current_metadata if unpacked else metadata,
        )

    async def _accept(
        self,
        candidate: Path,
        original_digest: str,
        limits: BinaryAnalysisLimits,
    ) -> tuple[Path, BinaryMetadata] | None:
        try:
            size = candidate.stat().st_size
        except OSError:
            return None
        if size < _XOR_MIN_SECTION_BYTES or size > limits.max_input_bytes:
            return None
        if await asyncio.to_thread(_file_digest, candidate) == original_digest:
            return None
        try:
            metadata = await asyncio.to_thread(inspect_binary, candidate, limits)
        except BinaryInspectionError:
            return await self._repair(candidate, limits)
        return candidate, metadata

    async def _repair(
        self, candidate: Path, limits: BinaryAnalysisLimits
    ) -> tuple[Path, BinaryMetadata] | None:
        rebuilder = self._rebuilder
        if rebuilder is None or not rebuilder.enabled:
            return None
        repaired = candidate.with_name(candidate.name + ".repaired.bin")
        if not await asyncio.to_thread(rebuilder.repair, candidate, repaired):
            return None
        try:
            metadata = await asyncio.to_thread(inspect_binary, repaired, limits)
        except BinaryInspectionError:
            return None
        return repaired, metadata


class BinaryUnpackSandboxAdapter:
    """Drive the isolated binary-unpack tool and read back its report."""

    name = "binary-unpack"

    def __init__(
        self,
        sandbox: BinaryFactsSandbox,
        store: LocalContentAddressedStore,
        *,
        image_digest: str,
        input_ref: str,
    ) -> None:
        self._sandbox = sandbox
        self._store = store
        self._image_digest = image_digest
        self._input_ref = input_ref

    async def unpack(
        self,
        artifact_kind: ArtifactKind,
        limits: BinaryAnalysisLimits,
        cancellation: asyncio.Event,
    ) -> UnpackChainOutcome:
        request = SandboxRequest(
            schema_version=SchemaVersion.VALUE_1_0_0,
            id=f"binary-unpack:{self._input_ref.removeprefix('cas://sha256/')}",
            tool_name=self.name,
            tool_version="1.0.0",
            image_digest=self._image_digest,
            artifact_kind=artifact_kind,
            input_ref=self._input_ref,
            arguments={},
            output_file_names=["binary-unpack.json", "unpacked.bin"],
            resource_budget=cast(
                ResourceBudget,
                {
                    # Same inert-bookkeeping values as the facts profile; the
                    # contract enforces minimums, so zeros are not legal here.
                    "max_model_tokens": 0,
                    "cpu_millis": 4000,
                    "memory_bytes": 3 * 1024 * 1024 * 1024,
                    "disk_bytes": 1024 * 1024 * 1024,
                    "max_tool_concurrency": 1,
                    "max_dynamic_runs": 0,
                    "timeout_seconds": _unpack_timeout(limits),
                },
            ),
            timeout_seconds=_unpack_timeout(limits),
        )
        result = await self._sandbox.run(request, cancellation)
        if result["status"] != "succeeded":
            # Carry the structured failure and the container's stderr tail into
            # the exception: the caller only logs the message, and without it a
            # degraded unpack is undiagnosable from the worker side.
            failure = json.dumps(result.get("failure") or {})[:400]
            stderr_tail = ""
            stderr_ref = result.get("stderr_ref")
            if stderr_ref:
                with self._store.open(stderr_ref) as stream:
                    stderr_tail = stream.read(2_048).decode("utf-8", "replace")[-400:]
            raise ToolExecutionError(
                f"binary-unpack sandbox execution failed: status={result['status']} "
                f"failure={failure} stderr={stderr_tail!r}"
            )
        report_output = next(
            (item for item in result["outputs"] if item["path"] == "binary-unpack.json"), None
        )
        if report_output is None:
            raise ToolExecutionError("binary-unpack report is missing")
        with self._store.open(report_output["object_ref"]) as stream:
            report = json.load(stream)
        stored: StoredObject | None = None
        if report.get("unpacked"):
            output = next(
                (item for item in result["outputs"] if item["path"] == "unpacked.bin"), None
            )
            if output is None:
                raise ToolExecutionError("binary-unpack output is missing")
            with self._store.open(output["object_ref"]) as source:
                stored = self._store.put_stream(source, max_bytes=limits.max_input_bytes)
            # The entrypoint reports a bare hex digest; CAS object refs carry
            # the sha256: prefix.  Compare the hex on both sides.
            reported = str(report.get("unpacked_digest") or "").lower().removeprefix(
                "sha256:"
            )
            if reported != stored.digest.removeprefix("sha256:"):
                raise ToolExecutionError("binary-unpack digest mismatch")
        return UnpackChainOutcome(
            runs=tuple(cast(list[BinaryToolRun], report.get("tool_runs") or [])),
            unpacked_path=None,
            stored=stored,
            method=cast(str | None, report.get("method")),
            methods=tuple(cast(list[str], report.get("methods") or [])),
            rounds=int(report.get("rounds") or 0),
            packed=bool(report.get("packed", True)),
            final_metadata=None,
        )


def _unpack_timeout(limits: BinaryAnalysisLimits) -> int:
    # Emulated unpacking of a stubborn shell legitimately takes longer than a
    # plain facts pass; scale the fixed command budget but keep a hard ceiling.
    return min(900, max(60, int(limits.command_timeout_seconds) * 5))


def _find_candidate(
    directory: Path, *, exclude: Path | None = None, prefer: str = ""
) -> Path | None:
    try:
        entries = [
            item
            for item in directory.iterdir()
            if item.is_file() and item != exclude and not item.name.startswith(".")
        ]
    except OSError:
        return None
    if not entries:
        return None
    if prefer:
        preferred = [item for item in entries if prefer in item.name]
        if preferred:
            entries = preferred
    return max(entries, key=lambda item: item.stat().st_size)


def _xor_recover(
    data: bytes,
    metadata: BinaryMetadata,
    min_entropy: float,
    max_bytes: int,
) -> bytes | None:
    for offset, size in _candidate_regions(data, metadata):
        size = min(size, max_bytes)
        if size < _XOR_MIN_SECTION_BYTES:
            continue
        blob = data[offset : offset + size]
        if len(blob) != size or shannon_entropy(blob) < min_entropy:
            continue
        for key in range(1, 256):
            if not _magic_matches(blob, key):
                continue
            decoded = blob.translate(_xor_table(key))
            if _plausible_container(decoded):
                return _trim_container(decoded)
    return None


def _trim_container(decoded: bytes) -> bytes:
    """Cut a recovered region down to the container's structural end.

    The XOR layer sits over a whole region, so the decode also covers whatever
    high-entropy padding followed the embedded image.  File size is derived
    from the container's own tables: section/segment ends for ELF, section
    raw ends for PE.  Any parse trouble keeps the untrimmed decode rather than
    guessing.
    """
    try:
        if decoded[:4] == b"\x7fELF":
            return decoded[: _elf_structural_end(decoded)]
        if decoded[:2] == b"MZ":
            return decoded[: _pe_structural_end(decoded)]
    except (IndexError, ValueError, struct.error):
        pass
    return decoded


def _elf_structural_end(decoded: bytes) -> int:
    is_64 = decoded[4] == 2
    little = decoded[5] == 1
    endian = "<" if little else ">"
    wide = "Q" if is_64 else "I"
    if is_64:
        phoff = struct.unpack_from(endian + "Q", decoded, 0x20)[0]
        shoff = struct.unpack_from(endian + "Q", decoded, 0x28)[0]
        phentsize, phnum, shentsize, shnum = struct.unpack_from(
            endian + "HHHH", decoded, 0x36
        )
        header_size = struct.unpack_from(endian + "H", decoded, 0x34)[0]
        segment_offset_field, segment_size_field = 8, 32  # p_offset, p_filesz
        section_offset_field, section_size_field = 0x18, 0x20
        section_entry = 64
    else:
        phoff = struct.unpack_from(endian + "I", decoded, 0x1C)[0]
        shoff = struct.unpack_from(endian + "I", decoded, 0x20)[0]
        phentsize, phnum, shentsize, shnum = struct.unpack_from(
            endian + "HHHH", decoded, 0x2A
        )
        header_size = struct.unpack_from(endian + "H", decoded, 0x28)[0]
        segment_offset_field, segment_size_field = 4, 16
        section_offset_field, section_size_field = 0x10, 0x14
        section_entry = 40
    ends = [header_size, phoff + phnum * phentsize, shoff + shnum * shentsize]
    for index in range(min(shnum, 65535)):
        position = shoff + index * shentsize
        if position + section_entry > len(decoded):
            break
        offset = struct.unpack_from(endian + wide, decoded, position + section_offset_field)[0]
        size = struct.unpack_from(endian + wide, decoded, position + section_size_field)[0]
        ends.append(offset + size)
    for index in range(min(phnum, 65535)):
        position = phoff + index * phentsize
        if position + phentsize > len(decoded):
            break
        offset = struct.unpack_from(
            endian + wide, decoded, position + segment_offset_field
        )[0]
        size = struct.unpack_from(endian + wide, decoded, position + segment_size_field)[0]
        ends.append(offset + size)
    end = max(ends)
    return end if 0 < end <= len(decoded) else len(decoded)


def _pe_structural_end(decoded: bytes) -> int:
    pe_offset = int.from_bytes(decoded[0x3C:0x40], "little")
    section_count = struct.unpack_from("<H", decoded, pe_offset + 6)[0]
    optional_size = struct.unpack_from("<H", decoded, pe_offset + 20)[0]
    section_offset = pe_offset + 24 + optional_size
    ends = [section_offset + section_count * 40]
    for index in range(min(section_count, 96)):
        position = section_offset + index * 40
        if position + 40 > len(decoded):
            break
        raw_size, raw_offset = struct.unpack_from("<II", decoded, position + 16)
        if raw_size:
            ends.append(raw_offset + raw_size)
    end = max(ends)
    return end if 0 < end <= len(decoded) else len(decoded)


def _candidate_regions(data: bytes, metadata: BinaryMetadata) -> list[tuple[int, int]]:
    """File regions a payload may hide in: sections, else executable segments.

    A hand-rolled ELF shell typically strips the section table, so the packed
    image's metadata carries no sections at all; its program headers remain the
    only map of where the encrypted body lives.
    """
    if metadata.sections:
        return [
            (section["file_offset"], section["file_size"]) for section in metadata.sections
        ]
    if metadata.format is not BinaryFormat.ELF:
        return []
    if len(data) < 64 or data[:4] != b"\x7fELF":
        return []
    is_64 = data[4] == 2
    little = data[5] == 1
    endian = "<" if little else ">"
    byte_order = "little" if little else "big"
    phoff = int.from_bytes(
        data[0x20:0x28] if is_64 else data[0x1C:0x20], byte_order
    )
    phentsize, phnum = struct.unpack_from(endian + "HH", data, 0x36 if is_64 else 0x2A)
    regions: list[tuple[int, int]] = []
    for index in range(min(phnum, 256)):
        position = phoff + index * phentsize
        if position + phentsize > len(data):
            break
        if is_64:
            segment_type = struct.unpack_from(endian + "I", data, position)[0]
            if segment_type != 1:  # PT_LOAD
                continue
            flags = struct.unpack_from(endian + "I", data, position + 4)[0]
            offset = struct.unpack_from(endian + "Q", data, position + 8)[0]
            size = struct.unpack_from(endian + "Q", data, position + 32)[0]
        else:
            segment_type = struct.unpack_from(endian + "I", data, position)[0]
            if segment_type != 1:  # PT_LOAD
                continue
            offset = struct.unpack_from(endian + "I", data, position + 4)[0]
            size = struct.unpack_from(endian + "I", data, position + 16)[0]
            flags = struct.unpack_from(endian + "I", data, position + 24)[0]
        if flags & 0x1:  # PF_X
            regions.append((offset, size))
    return regions


def _xor_table(key: int) -> bytes:
    return bytes(value ^ key for value in range(256))


def _magic_matches(blob: bytes, key: int) -> bool:
    head = blob[:4]
    if bytes((head[0] ^ key, head[1] ^ key, head[2] ^ key, head[3] ^ key)) == b"\x7fELF":
        return True
    return (head[0] ^ key, head[1] ^ key) == (0x4D, 0x5A)


def _plausible_container(candidate: bytes) -> bool:
    if candidate[:4] == b"\x7fELF":
        return len(candidate) >= 16 and candidate[4] in (1, 2) and candidate[5] in (1, 2)
    if candidate[:2] == b"MZ":
        if len(candidate) < 0x40:
            return False
        pe_offset = int.from_bytes(candidate[0x3C:0x40], "little")
        return (
            pe_offset >= 0x40
            and pe_offset + 24 <= len(candidate)
            and candidate[pe_offset : pe_offset + 4] == b"PE\0\0"
        )
    return False


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
