from __future__ import annotations

from pathlib import Path

import pytest
from vulnweaver_binary_analysis import (
    BinaryAnalysisLimits,
    BinaryInspectionError,
    extract_strings,
    inspect_binary,
)

from tests.binary_analysis.samples import elf64_sample, pe64_sample


def test_inspects_x64_elf_sections_and_addresses(tmp_path: Path) -> None:
    sample = tmp_path / "sample.elf"
    sample.write_bytes(elf64_sample())
    metadata = inspect_binary(sample)
    assert metadata.format == "elf"
    assert metadata.architecture == "x86_64"
    assert metadata.bits == 64
    assert metadata.image_base == 0x400000
    assert metadata.entry_point == 0x401000
    assert metadata.sections[0]["name"] == ".text"
    assert metadata.sections[0]["executable"] is True
    assert metadata.virtual_address_to_offset(0x401003) == 0x203
    assert metadata.offset_to_virtual_address(0x203) == 0x401003


def test_detects_upx_section_without_executing_sample(tmp_path: Path) -> None:
    sample = tmp_path / "packed.elf"
    sample.write_bytes(elf64_sample(upx_section=True))
    metadata = inspect_binary(sample)
    assert metadata.packed is True
    assert metadata.packer == "UPX"


def test_inspects_x64_pe_and_extracts_strings(tmp_path: Path) -> None:
    sample = tmp_path / "sample.exe"
    sample.write_bytes(pe64_sample())
    metadata = inspect_binary(sample)
    strings = extract_strings(
        sample, metadata, BinaryAnalysisLimits(max_strings=20, min_string_chars=5)
    )
    assert metadata.format == "pe"
    assert metadata.architecture == "x86_64"
    assert metadata.image_base == 0x140000000
    assert metadata.entry_point == 0x140001000
    assert metadata.sections[0]["virtual_address"] == 0x140001000
    assert any(item["value"] == "hello-binary" for item in strings)


@pytest.mark.parametrize(
    ("content", "code"),
    [
        (b"not-a-binary", "unsupported_format"),
        (elf64_sample(machine=183), "unsupported_architecture"),
        (pe64_sample(machine=0xAA64), "unsupported_architecture"),
    ],
)
def test_rejects_inputs_outside_the_binary_scope(tmp_path: Path, content: bytes, code: str) -> None:
    sample = tmp_path / "unsupported.bin"
    sample.write_bytes(content)
    with pytest.raises(BinaryInspectionError) as captured:
        inspect_binary(sample)
    assert captured.value.code == code


def test_rejects_section_ranges_outside_the_file(tmp_path: Path) -> None:
    content = bytearray(elf64_sample())
    content[0x80 + 64 + 32 : 0x80 + 64 + 40] = (2**63).to_bytes(8, "little")
    sample = tmp_path / "truncated.elf"
    sample.write_bytes(content)
    with pytest.raises(BinaryInspectionError) as captured:
        inspect_binary(sample)
    assert captured.value.code == "invalid_range"
