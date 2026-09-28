from __future__ import annotations

import asyncio
import io
import json
import struct
from collections.abc import Sequence
from pathlib import Path
from typing import cast

import pytest
from vulnweaver_artifact_store import LocalContentAddressedStore
from vulnweaver_binary_analysis import (
    BinaryAnalysisLimits,
    BinaryMetadata,
    BinaryUnpackSandboxAdapter,
    De4dotUnpacker,
    LiefRebuilder,
    UnipackerUnpacker,
    UnpackAttempt,
    UnpackerChain,
    UpxCliUnpacker,
    XorRegionUnpacker,
    inspect_binary,
)
from vulnweaver_binary_analysis.tools import CommandResult, ToolExecutionError
from vulnweaver_binary_analysis.types import UpxOutcome
from vulnweaver_contracts import (
    ArtifactKind,
    BinaryArchitecture,
    BinaryFormat,
    BinaryToolRun,
    SandboxResult,
    SandboxStatus,
    StaticToolStatus,
    validate_contract,
)

from tests.binary_analysis.samples import elf64_sample, packed_elf64_sample, pe64_sample

LIMITS = BinaryAnalysisLimits(max_functions=64, max_instructions=512)
XOR_KEY = 0x5A


class _FakeUnpacker:
    """Scripted chain member: writes one payload per call, then goes quiet."""

    def __init__(
        self,
        name: str,
        payloads: Sequence[bytes],
        *,
        supports_result: bool = True,
    ) -> None:
        self.name = name
        self._payloads = list(payloads)
        self._supports = supports_result
        self.calls = 0

    def supports(self, metadata: BinaryMetadata) -> bool:
        del metadata
        return self._supports

    async def unpack(
        self,
        path: Path,
        workdir: Path,
        limits: BinaryAnalysisLimits,
        cancellation: asyncio.Event,
    ) -> UnpackAttempt:
        del path, limits, cancellation
        self.calls += 1
        if not self._payloads:
            return UnpackAttempt(
                self.name,
                _static_run(self.name, "nothing_left"),
            )
        destination = workdir / f"{self.name}-candidate.bin"
        destination.write_bytes(self._payloads.pop(0))
        return UnpackAttempt(self.name, _static_run(self.name, "unpacked"), destination)


def _static_run(name: str, reason: str) -> BinaryToolRun:
    return BinaryToolRun(
        tool_name=name,
        tool_version=None,
        status=StaticToolStatus.SUCCEEDED,
        exit_code=None,
        reason=reason,
        raw_output=None,
    )


def _run(coro):
    return asyncio.run(coro)


def _artifact_kind() -> ArtifactKind:
    return cast(ArtifactKind, _native_pe_metadata().format)


def _dotnet_pe_metadata() -> BinaryMetadata:
    return BinaryMetadata(
        format=BinaryFormat.PE,
        architecture=BinaryArchitecture.X86_64,
        bits=64,
        endianness="little",
        image_base=0x140000000,
        entry_point=0x140001000,
        sections=(),
        packed=True,
        packer="ConfuserEx",
        dotnet=True,
    )


def _native_pe_metadata(*, packed: bool = True) -> BinaryMetadata:
    return BinaryMetadata(
        format=BinaryFormat.PE,
        architecture=BinaryArchitecture.X86_64,
        bits=64,
        endianness="little",
        image_base=0x140000000,
        entry_point=0x140001000,
        sections=(),
        packed=packed,
    )


def _xor_outer_sample() -> tuple[bytes, bytes]:
    """A section-less packed ELF whose executable segment starts with a XORed ELF."""
    outer = bytearray(packed_elf64_sample(keep_sections=False, alphabet=256))
    inner = elf64_sample()
    outer[0x1000 : 0x1000 + len(inner)] = bytes(value ^ XOR_KEY for value in inner)
    return bytes(outer), inner


def test_chain_accepts_first_valid_candidate(tmp_path: Path) -> None:
    original = tmp_path / "input.bin"
    original.write_bytes(packed_elf64_sample(keep_sections=False))
    unpacker = _FakeUnpacker("upx", [elf64_sample()])
    outcome = _run(
        UnpackerChain((unpacker,), rebuilder=None).run(
            original, inspect_binary(original, LIMITS), LIMITS, asyncio.Event()
        )
    )
    assert outcome.unpacked_path is not None
    assert outcome.unpacked_path.read_bytes() == elf64_sample()
    assert outcome.method == "upx"
    assert outcome.methods == ("upx",)
    assert not outcome.packed
    assert outcome.final_metadata is not None and not outcome.final_metadata.packed


def test_chain_rejects_identical_candidate(tmp_path: Path) -> None:
    original_bytes = packed_elf64_sample(keep_sections=False)
    original = tmp_path / "input.bin"
    original.write_bytes(original_bytes)
    outcome = _run(
        UnpackerChain((_FakeUnpacker("upx", [original_bytes]),), rebuilder=None).run(
            original, inspect_binary(original, LIMITS), LIMITS, asyncio.Event()
        )
    )
    assert outcome.unpacked_path is None
    assert outcome.method is None
    assert outcome.runs and outcome.runs[0]["tool_name"] == "upx"


def test_chain_rejects_unparseable_candidate(tmp_path: Path) -> None:
    original = tmp_path / "input.bin"
    original.write_bytes(packed_elf64_sample(keep_sections=False))
    garbage = bytes(range(256)) * 4  # 1024 bytes, no container magic
    outcome = _run(
        UnpackerChain((_FakeUnpacker("upx", [garbage]),), rebuilder=None).run(
            original, inspect_binary(original, LIMITS), LIMITS, asyncio.Event()
        )
    )
    assert outcome.unpacked_path is None
    assert outcome.packed


def test_chain_peels_nested_layers(tmp_path: Path) -> None:
    original = tmp_path / "input.bin"
    original.write_bytes(packed_elf64_sample(keep_sections=False))
    inner_packed = packed_elf64_sample(keep_sections=False, alphabet=150)
    outer_layer = _FakeUnpacker("layer-a", [inner_packed])
    inner_layer = _FakeUnpacker("layer-b", [elf64_sample()])
    outcome = _run(
        UnpackerChain((outer_layer, inner_layer), rebuilder=None).run(
            original, inspect_binary(original, LIMITS), LIMITS, asyncio.Event()
        )
    )
    assert outcome.methods == ("layer-a", "layer-b")
    assert outcome.rounds == 1
    assert outcome.unpacked_path is not None
    assert outcome.unpacked_path.read_bytes() == elf64_sample()


def test_xor_recovery_unpacks_sectionless_packed_elf(tmp_path: Path) -> None:
    outer_bytes, inner = _xor_outer_sample()
    outer = tmp_path / "input.bin"
    outer.write_bytes(outer_bytes)
    metadata = inspect_binary(outer, LIMITS)
    assert metadata.packed and metadata.packer is None
    workdir = tmp_path / "work"
    workdir.mkdir()
    attempt = _run(
        XorRegionUnpacker().unpack(outer, workdir, LIMITS, asyncio.Event())
    )
    assert attempt.candidate_path is not None
    assert attempt.candidate_path.read_bytes() == inner
    assert attempt.run["reason"] == "recovered"


def test_xor_recovery_reports_nothing_without_payload(tmp_path: Path) -> None:
    outer = tmp_path / "input.bin"
    outer.write_bytes(packed_elf64_sample(keep_sections=False, alphabet=256))
    workdir = tmp_path / "work"
    workdir.mkdir()
    attempt = _run(
        XorRegionUnpacker().unpack(outer, workdir, LIMITS, asyncio.Event())
    )
    assert attempt.candidate_path is None
    assert attempt.run["reason"] == "no_recoverable_payload"


def test_de4dot_supports_requires_packed_dotnet_pe() -> None:
    unpacker = De4dotUnpacker()
    assert unpacker.supports(_dotnet_pe_metadata())
    assert not unpacker.supports(_native_pe_metadata())
    assert not unpacker.supports(
        BinaryMetadata(
            format=BinaryFormat.ELF,
            architecture=BinaryArchitecture.X86_64,
            bits=64,
            endianness="little",
            image_base=0x400000,
            entry_point=0x401000,
            sections=(),
            packed=True,
            dotnet=True,
        )
    )


class _MonoRunner:
    def __init__(self, payload: bytes) -> None:
        self._payload = payload
        self.commands: list[tuple[str, ...]] = []

    async def run(
        self,
        arguments: Sequence[str],
        *,
        timeout_seconds: float,
        max_output_bytes: int,
        cancellation: asyncio.Event,
        cwd: Path | None = None,
    ) -> CommandResult:
        del timeout_seconds, max_output_bytes, cancellation
        self.commands.append(tuple(arguments))
        assert cwd is not None
        (cwd / "sample-cleaned.bin").write_bytes(self._payload)
        return CommandResult(0, b"Cleaned sample.bin\n", b"")


def test_de4dot_invokes_mono_and_picks_cleaned_output(tmp_path: Path) -> None:
    source = tmp_path / "input.bin"
    source.write_bytes(pe64_sample())
    runner = _MonoRunner(elf64_sample())
    workdir = tmp_path / "work"
    workdir.mkdir()
    attempt = _run(
        De4dotUnpacker("/opt/de4dot/de4dot.exe", runner=runner).unpack(
            source, workdir, LIMITS, asyncio.Event()
        )
    )
    assert runner.commands and runner.commands[0][0] == "mono"
    assert runner.commands[0][1] == "/opt/de4dot/de4dot.exe"
    assert attempt.candidate_path is not None
    assert "-cleaned" in attempt.candidate_path.name
    assert attempt.run["status"] is StaticToolStatus.SUCCEEDED


class _DumpRunner:
    def __init__(self, payload: bytes) -> None:
        self._payload = payload

    async def run(
        self,
        arguments: Sequence[str],
        *,
        timeout_seconds: float,
        max_output_bytes: int,
        cancellation: asyncio.Event,
        cwd: Path | None = None,
    ) -> CommandResult:
        del timeout_seconds, max_output_bytes, cancellation, cwd
        dumps = Path(arguments[3])
        dumps.mkdir(exist_ok=True)
        (dumps / "sample-unpacked.exe").write_bytes(self._payload)
        return CommandResult(0, b"dumped\n", b"")


def test_unipacker_invokes_cli_and_picks_dump(tmp_path: Path) -> None:
    source = tmp_path / "input.bin"
    source.write_bytes(pe64_sample())
    runner = _DumpRunner(elf64_sample())
    workdir = tmp_path / "work"
    workdir.mkdir()
    attempt = _run(
        UnipackerUnpacker("unipacker", runner=runner).unpack(
            source, workdir, LIMITS, asyncio.Event()
        )
    )
    assert attempt.candidate_path is not None
    assert attempt.candidate_path.read_bytes() == elf64_sample()
    assert attempt.run["reason"] == "unpacked"


def test_unipacker_degrades_when_missing(tmp_path: Path) -> None:
    source = tmp_path / "input.bin"
    source.write_bytes(pe64_sample())
    workdir = tmp_path / "work"
    workdir.mkdir()
    attempt = _run(
        UnipackerUnpacker("definitely-not-on-path").unpack(
            source, workdir, LIMITS, asyncio.Event()
        )
    )
    assert attempt.candidate_path is None
    assert attempt.run["status"] is StaticToolStatus.UNAVAILABLE


def test_upx_cli_unpacker_wraps_upx_protocol(tmp_path: Path) -> None:
    class _Unpacks:
        async def unpack(self, path, destination, limits, cancellation) -> UpxOutcome:
            del path, limits, cancellation
            destination.write_bytes(elf64_sample())
            return UpxOutcome(
                run=_static_run("upx", "unpacked"), packed=True, unpacked_path=destination
            )

    source = tmp_path / "input.bin"
    source.write_bytes(packed_elf64_sample(keep_sections=False))
    workdir = tmp_path / "work"
    workdir.mkdir()
    attempt = _run(
        UpxCliUnpacker(upx=_Unpacks()).unpack(source, workdir, LIMITS, asyncio.Event())
    )
    assert attempt.candidate_path is not None
    assert attempt.candidate_path.name == "upx-unpacked.bin"


def test_lief_rebuilder_disabled_short_circuits(tmp_path: Path) -> None:
    source = tmp_path / "input.bin"
    source.write_bytes(pe64_sample())
    destination = tmp_path / "repaired.bin"
    assert not LiefRebuilder(enabled=False).repair(source, destination)


def test_inspect_pe_detects_clr_directory(tmp_path: Path) -> None:
    plain = tmp_path / "plain.exe"
    plain.write_bytes(pe64_sample())
    assert not inspect_binary(plain, LIMITS).dotnet

    managed = bytearray(pe64_sample())
    optional = 0x80 + 24
    struct.pack_into("<I", managed, optional + 108, 16)  # NumberOfRvaAndSizes
    struct.pack_into("<II", managed, optional + 112 + 14 * 8, 0x2000, 0x48)  # CLR header
    managed_path = tmp_path / "managed.exe"
    managed_path.write_bytes(bytes(managed))
    assert inspect_binary(managed_path, LIMITS).dotnet


class _Sandbox:
    def __init__(self, result: SandboxResult) -> None:
        self.result = result
        self.request = None

    async def run(self, request, cancellation: asyncio.Event) -> SandboxResult:
        del cancellation
        self.request = request
        return self.result


def test_binary_unpack_sandbox_adapter_round_trips_report(tmp_path: Path) -> None:
    store = LocalContentAddressedStore(tmp_path / "cas")
    inner = elf64_sample()
    stored_inner = store.put_stream(io.BytesIO(inner), max_bytes=1024 * 1024)
    report = {
        "schema_version": "1.0.0",
        "unpacked": True,
        "method": "unipacker",
        "methods": ["upx", "unipacker"],
        "rounds": 1,
        "packed": False,
        "unpacked_digest": stored_inner.digest.removeprefix("sha256:"),
        "tool_runs": [dict(_static_run("unipacker", "unpacked"))],
    }
    stored_report = store.put_stream(
        io.BytesIO(json.dumps(report).encode()), max_bytes=1024 * 1024
    )
    result = SandboxResult(
        schema_version="1.0.0",
        request_id="request-1",
        status=SandboxStatus.SUCCEEDED,
        exit_code=0,
        stdout_ref=None,
        stderr_ref=None,
        outputs=[
            {
                "path": "binary-unpack.json",
                "object_ref": stored_report.object_ref,
                "digest": stored_report.digest,
                "size_bytes": stored_report.size_bytes,
            },
            {
                "path": "unpacked.bin",
                "object_ref": stored_inner.object_ref,
                "digest": stored_inner.digest,
                "size_bytes": stored_inner.size_bytes,
            },
        ],
        resource_usage={
            "duration_millis": 1,
            "cpu_millis": 1,
            "memory_bytes": 1,
            "output_bytes": stored_report.size_bytes,
        },
        failure=None,
    )
    sandbox = _Sandbox(result)

    class _ContractCheckingSandbox(_Sandbox):
        async def run(self, request, cancellation):
            validate_contract("SandboxRequest", request)
            return await super().run(request, cancellation)

    sandbox = _ContractCheckingSandbox(result)
    outcome = _run(
        BinaryUnpackSandboxAdapter(
            sandbox,
            store,
            image_digest="sha256:" + "a" * 64,
            input_ref=f"cas://sha256/{'b' * 64}",
        ).unpack(_artifact_kind(), LIMITS, asyncio.Event())
    )
    assert sandbox.request is not None
    assert sandbox.request["tool_name"] == "binary-unpack"
    assert outcome.stored is not None
    assert outcome.stored.digest == stored_inner.digest
    assert outcome.method == "unipacker"
    assert outcome.methods == ("upx", "unipacker")
    assert not outcome.packed
    assert outcome.unpacked_path is None  # the caller materializes it


def test_binary_unpack_sandbox_adapter_rejects_digest_mismatch(tmp_path: Path) -> None:
    store = LocalContentAddressedStore(tmp_path / "cas")
    inner = elf64_sample()
    stored_inner = store.put_stream(io.BytesIO(inner), max_bytes=1024 * 1024)
    report = {
        "schema_version": "1.0.0",
        "unpacked": True,
        "method": "unipacker",
        "methods": ["unipacker"],
        "rounds": 0,
        "packed": False,
        "unpacked_digest": "0" * 64,
        "tool_runs": [],
    }
    stored_report = store.put_stream(
        io.BytesIO(json.dumps(report).encode()), max_bytes=1024 * 1024
    )
    result = SandboxResult(
        schema_version="1.0.0",
        request_id="request-2",
        status=SandboxStatus.SUCCEEDED,
        exit_code=0,
        stdout_ref=None,
        stderr_ref=None,
        outputs=[
            {
                "path": "binary-unpack.json",
                "object_ref": stored_report.object_ref,
                "digest": stored_report.digest,
                "size_bytes": stored_report.size_bytes,
            },
            {
                "path": "unpacked.bin",
                "object_ref": stored_inner.object_ref,
                "digest": stored_inner.digest,
                "size_bytes": stored_inner.size_bytes,
            },
        ],
        resource_usage={
            "duration_millis": 1,
            "cpu_millis": 1,
            "memory_bytes": 1,
            "output_bytes": stored_report.size_bytes,
        },
        failure=None,
    )
    with pytest.raises(ToolExecutionError):
        _run(
            BinaryUnpackSandboxAdapter(
                _Sandbox(result),
                store,
                image_digest="sha256:" + "a" * 64,
                input_ref=f"cas://sha256/{'b' * 64}",
            ).unpack(_artifact_kind(), LIMITS, asyncio.Event())
        )
