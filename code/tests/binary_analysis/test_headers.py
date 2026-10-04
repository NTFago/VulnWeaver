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
from tests.binary_analysis.test_coverage import _metadata


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
    extraction = extract_strings(
        sample, metadata, BinaryAnalysisLimits(max_strings=20, min_string_chars=5)
    )
    strings = extraction.strings
    assert metadata.format == "pe"
    assert metadata.architecture == "x86_64"
    assert metadata.image_base == 0x140000000
    assert metadata.entry_point == 0x140001000
    assert metadata.sections[0]["virtual_address"] == 0x140001000
    assert any(item["value"] == "hello-binary" for item in strings)
    assert extraction.offered == len(strings)
    assert extraction.truncated is False


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


def test_pe_with_virtual_only_executable_section_is_packed(tmp_path) -> None:
    import struct as _struct

    from tests.binary_analysis.samples import pe64_sample

    # A packed PE's hallmark: an executable section with virtual size but no
    # file backing, which the unpacking stub fills at runtime.  Ordinary
    # uninitialized sections (.bss) are never executable and cannot fire this.
    section_offset = 0x80 + 24 + 0xF0
    data = bytearray(pe64_sample())
    _struct.pack_into("<IIII", data, section_offset + 8, 0x2000, 0x1000, 0, 0)
    packed = tmp_path / "virtual-only.exe"
    packed.write_bytes(bytes(data))
    plain = tmp_path / "plain.exe"
    plain.write_bytes(pe64_sample())

    assert inspect_binary(packed, BinaryAnalysisLimits()).packed
    assert not inspect_binary(plain, BinaryAnalysisLimits()).packed


def test_a_printable_run_at_the_end_of_the_image_is_still_a_string(tmp_path: Path) -> None:
    """The scan covers the image itself; nothing is appended to flush the tail."""
    sample = tmp_path / "tail.bin"
    sample.write_bytes(b"\x00\x00trailing-run")
    extraction = extract_strings(
        sample, _metadata(), BinaryAnalysisLimits(min_string_chars=4)
    )
    assert [item["value"] for item in extraction.strings] == ["trailing-run"]
    assert extraction.strings[0]["file_offset"] == 2


def test_long_utf16_run_is_reported_as_consecutive_windows(tmp_path: Path) -> None:
    """A UTF-16 run past ``max_string_chars`` splits the way it always has.

    The byte-by-byte scan this replaced stopped a record at the cap, stepped
    past the character it stopped on, and carried on, so windows begin
    ``max_string_chars + 1`` characters apart. Pin it: the offsets are not
    something a reader would guess.
    """
    sample = tmp_path / "wide.bin"
    sample.write_bytes(("ABCDEFGHIJKLMNOPQRSTUVWXYZ" * 4).encode("utf-16-le"))
    extraction = extract_strings(
        sample,
        _metadata(),
        BinaryAnalysisLimits(max_strings=20, min_string_chars=4, max_string_chars=8),
    )
    assert [item["value"] for item in extraction.strings] == [
        "ABCDEFGH",
        "JKLMNOPQ",
        "STUVWXYZ",
        "BCDEFGHI",
        "KLMNOPQR",
        "TUVWXYZA",
        "CDEFGHIJ",
        "LMNOPQRS",
        "UVWXYZAB",
        "DEFGHIJK",
        "MNOPQRST",
        "VWXYZ",
    ]
    assert [item["file_offset"] for item in extraction.strings] == list(range(0, 200, 18))
    assert extraction.offered == 12


def test_long_ascii_run_is_one_record_with_a_capped_value(tmp_path: Path) -> None:
    """The value is capped; the run is not split."""
    sample = tmp_path / "long.bin"
    sample.write_bytes(b"X" * 50)
    extraction = extract_strings(
        sample, _metadata(), BinaryAnalysisLimits(min_string_chars=4, max_string_chars=6)
    )
    assert [item["value"] for item in extraction.strings] == ["XXXXXX"]
    assert extraction.offered == 1


def test_offered_counts_every_run_across_both_encodings(tmp_path: Path) -> None:
    """``offered`` stays an exact count of candidates, cap or no cap (CR-08)."""
    sample = tmp_path / "both.bin"
    sample.write_bytes(
        b"".join(b"ascii-%02d\x00" % index for index in range(6))
        # No separator between them, so the four wide strings are one UTF-16 run.
        + "".join(f"wide-{index:02d}" for index in range(4)).encode("utf-16-le")
    )
    limits = BinaryAnalysisLimits(max_strings=2, min_string_chars=4)
    extraction = extract_strings(sample, _metadata(), limits)
    assert [item["value"] for item in extraction.strings] == ["ascii-00", "ascii-01"]
    # Six ASCII runs plus the one UTF-16 run, against a cap of two.
    assert extraction.offered == 7
    assert extraction.truncated is True


def test_utf16_scan_only_sees_even_pair_starts(tmp_path: Path) -> None:
    """Characterises the UTF-16 walk, whose output must not drift.

    It steps two bytes at a time from offset 0, so it only ever tries even pair
    starts. A run one byte late is perfectly good UTF-16LE and still invisible,
    and plain ASCII is read as pairs with deterministic junk. Both show up in
    what a binary is reported to contain, which is why this pass stays
    byte-by-byte instead of being vectorised like the ASCII one.
    """
    odd = tmp_path / "odd.bin"
    odd.write_bytes(b"\x7f" + "wide-string".encode("utf-16-le"))
    extraction = extract_strings(
        odd, _metadata(), BinaryAnalysisLimits(min_string_chars=4)
    )
    assert extraction.strings == ()
    assert extraction.offered == 0

    # The same run one byte earlier is found in full — the alignment is the
    # whole difference, not the bytes.
    even = tmp_path / "even.bin"
    even.write_bytes(b"\x00\x00" + "wide-string".encode("utf-16-le"))
    aligned = extract_strings(even, _metadata(), BinaryAnalysisLimits(min_string_chars=4))
    assert [item["value"] for item in aligned.strings] == ["wide-string"]
    assert [item["file_offset"] for item in aligned.strings] == [2]
