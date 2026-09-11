from __future__ import annotations

from pathlib import Path

import pytest
from vulnweaver_binary_analysis import (
    BinaryAnalysisLimits,
    BinaryInspectionError,
    extract_strings,
    inspect_binary,
)

from tests.binary_analysis.samples import elf64_sample, packed_elf64_sample, pe64_sample


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


def test_detects_packed_elf_that_names_no_packer(tmp_path: Path) -> None:
    """The container is rebuilt and the segment is compressed, but nothing is named.

    This is how UPX presents on linux/amd64: the section header table is gone, so
    the section-name rule has nothing to match on and packing went unreported.
    """
    sample = tmp_path / "packed.elf"
    sample.write_bytes(packed_elf64_sample(alphabet=150))
    metadata = inspect_binary(sample)
    assert metadata.sections == ()
    assert metadata.packed is True
    assert metadata.packer is None


def test_detects_encrypted_segment_behind_intact_sections(tmp_path: Path) -> None:
    """An encrypted body is flagged on entropy alone, whatever the container looks like."""
    sample = tmp_path / "encrypted.elf"
    sample.write_bytes(packed_elf64_sample(keep_sections=True, alphabet=256))
    metadata = inspect_binary(sample)
    assert len(metadata.sections) == 2
    assert metadata.packed is True
    assert metadata.packer is None


def test_does_not_flag_a_normally_linked_elf(tmp_path: Path) -> None:
    sample = tmp_path / "sample.elf"
    sample.write_bytes(elf64_sample())
    metadata = inspect_binary(sample)
    assert metadata.packed is False
    assert metadata.packer is None


def test_does_not_flag_weakly_compressed_body_with_intact_sections(tmp_path: Path) -> None:
    """Documents a known limit rather than pretending the heuristic is total.

    A shell that keeps the section table *and* compresses below the entropy floor
    is not caught here; DIE and the UPX probe are what cover that case.
    """
    sample = tmp_path / "quiet.elf"
    sample.write_bytes(packed_elf64_sample(keep_sections=True, alphabet=150))
    metadata = inspect_binary(sample)
    assert metadata.packed is False


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
