"""Bounded ELF/PE header parsing and inert string extraction."""

from __future__ import annotations

import math
import struct
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Literal

from vulnweaver_contracts import (
    BinaryArchitecture,
    BinaryFormat,
    BinarySection,
    BinaryString,
)

from vulnweaver_binary_analysis.types import BinaryAnalysisLimits, BinaryMetadata

_ELF_MAGIC = b"\x7fELF"
_PE_MAGIC = b"MZ"
_ELF_PT_LOAD = 1
_ELF_PF_EXECUTE = 0x1
_ELF_SHF_WRITE = 0x1
_ELF_SHF_ALLOC = 0x2
_ELF_SHF_EXECINSTR = 0x4
_ELF_SHT_NOBITS = 8
_PE_MEM_EXECUTE = 0x20000000
_PE_MEM_READ = 0x40000000
_PE_MEM_WRITE = 0x80000000

# Packer heuristic thresholds.  Calibrated on 907 ordinary ELF objects from the
# toolchain image: the highest executable-segment entropy any of them reached was
# 6.817 (libdav1d, hand-written SIMD), and the lowest section-header count was 21.
# A real UPX-packed linux/amd64 binary measures 7.26 entropy with 0 section
# headers and 3 program headers.  The thresholds sit between those populations.
_ENTROPY_ENCRYPTED = 7.5
_ENTROPY_PACKED = 7.0
_MIN_ENTROPY_BYTES = 4096
_MAX_PACKED_PROGRAM_HEADERS = 5


@dataclass(frozen=True, slots=True)
class _ContainerLayout:
    """Structural facts the packer heuristic needs, which BinaryMetadata omits.

    `sections` in the metadata drops the null section and is empty whenever the
    section header table is absent, so the declared counts are tracked here.
    """

    declared_sections: int
    declared_program_headers: int
    executable_regions: tuple[tuple[int, int], ...]


class BinaryInspectionError(ValueError):
    """The artifact is not a supported, structurally valid x86/x64 ELF or PE image."""

    def __init__(
        self, code: str, message: str, *, details: dict[str, object] | None = None
    ) -> None:
        self.code = code
        self.message = message
        self.details = dict(details or {})
        super().__init__(message)


def inspect_binary(path: str | Path, limits: BinaryAnalysisLimits | None = None) -> BinaryMetadata:
    configured = limits or BinaryAnalysisLimits()
    target = Path(path)
    size = target.stat().st_size
    if size < 4:
        raise BinaryInspectionError("truncated", "binary input is too small")
    if size > configured.max_input_bytes:
        raise BinaryInspectionError(
            "too_large",
            "binary input exceeds the configured size limit",
            details={"size_bytes": size, "max_bytes": configured.max_input_bytes},
        )
    data = target.read_bytes()
    if data.startswith(_ELF_MAGIC):
        metadata, layout = _inspect_elf(data, configured)
    elif data.startswith(_PE_MAGIC):
        metadata, layout = _inspect_pe(data, configured)
    else:
        raise BinaryInspectionError("unsupported_format", "only ELF and PE inputs are supported")
    packer = _packer_from_sections(metadata.sections)
    if packer is not None:
        return replace(metadata, packed=True, packer=packer)
    if _heuristic_packed(data, layout):
        # Packed, but nothing names the shell.  `packed=true, packer=null` is the
        # honest reading for a shell that leaves no recognised section name: UPX
        # on linux/amd64 strips the section header table, and custom
        # self-decrypting stubs never had one to begin with.
        return replace(metadata, packed=True, packer=None)
    return replace(metadata, packed=False, packer=None)


def extract_strings(
    path: str | Path,
    metadata: BinaryMetadata,
    limits: BinaryAnalysisLimits | None = None,
) -> tuple[BinaryString, ...]:
    configured = limits or BinaryAnalysisLimits()
    data = Path(path).read_bytes()
    records: list[BinaryString] = []
    records.extend(_ascii_strings(data, metadata, configured))
    if len(records) < configured.max_strings:
        records.extend(
            _utf16le_strings(data, metadata, configured, configured.max_strings - len(records))
        )
    records.sort(key=lambda item: (item["file_offset"], item["encoding"]))
    return tuple(records[: configured.max_strings])


def _inspect_elf(
    data: bytes, limits: BinaryAnalysisLimits
) -> tuple[BinaryMetadata, _ContainerLayout]:
    if len(data) < 16:
        raise BinaryInspectionError("truncated_elf", "ELF identification header is truncated")
    elf_class = data[4]
    data_encoding = data[5]
    if elf_class not in (1, 2):
        raise BinaryInspectionError("unsupported_elf_class", "ELF class must be 32 or 64 bit")
    if data_encoding not in (1, 2):
        raise BinaryInspectionError("unsupported_endianness", "ELF endianness is unsupported")
    bits: Literal[32, 64] = 32 if elf_class == 1 else 64
    endian: Literal["little", "big"] = "little" if data_encoding == 1 else "big"
    prefix = "<" if data_encoding == 1 else ">"
    header_size = 52 if bits == 32 else 64
    if len(data) < header_size:
        raise BinaryInspectionError("truncated_elf", "ELF header is truncated")
    if bits == 32:
        values = _unpack_from(prefix + "HHIIIIIHHHHHH", data, 16, "ELF header")
        machine = values[1]
        entry, phoff, shoff = values[3], values[4], values[5]
        phentsize, phnum = values[8], values[9]
        shentsize, shnum, shstrndx = values[10], values[11], values[12]
        expected_ph_size, expected_sh_size = 32, 40
    else:
        values = _unpack_from(prefix + "HHIQQQIHHHHHH", data, 16, "ELF header")
        machine = values[1]
        entry, phoff, shoff = values[3], values[4], values[5]
        phentsize, phnum = values[8], values[9]
        shentsize, shnum, shstrndx = values[10], values[11], values[12]
        expected_ph_size, expected_sh_size = 56, 64
    architecture = _elf_architecture(machine)
    image_base = _elf_image_base(
        data,
        bits=bits,
        prefix=prefix,
        offset=phoff,
        entry_size=phentsize,
        count=phnum,
        expected_size=expected_ph_size,
    )
    sections = _elf_sections(
        data,
        bits=bits,
        prefix=prefix,
        offset=shoff,
        entry_size=shentsize,
        count=shnum,
        string_index=shstrndx,
        expected_size=expected_sh_size,
        limit=limits.max_sections,
    )
    return (
        BinaryMetadata(
            format=BinaryFormat.ELF,
            architecture=architecture,
            bits=bits,
            endianness=endian,
            image_base=image_base,
            entry_point=entry,
            sections=sections,
        ),
        _ContainerLayout(
            declared_sections=shnum,
            declared_program_headers=phnum,
            executable_regions=_elf_executable_regions(
                data,
                bits=bits,
                prefix=prefix,
                offset=phoff,
                entry_size=phentsize,
                count=phnum,
                expected_size=expected_ph_size,
            ),
        ),
    )


def _elf_executable_regions(
    data: bytes,
    *,
    bits: int,
    prefix: str,
    offset: int,
    entry_size: int,
    count: int,
    expected_size: int,
) -> tuple[tuple[int, int], ...]:
    """(file_offset, file_size) of every executable PT_LOAD segment.

    Program headers rather than sections: a packed ELF may carry no section
    header table at all, which is exactly the case this heuristic must cover.
    """
    if count == 0:
        return ()
    _validate_table(data, offset, entry_size, count, expected_size, "ELF program header")
    regions: list[tuple[int, int]] = []
    for index in range(count):
        position = offset + index * entry_size
        if bits == 32:
            values = _unpack_from(prefix + "IIIIIIII", data, position, "ELF program header")
            segment_type, flags, file_offset, file_size = (
                values[0],
                values[1],
                values[2],
                values[4],
            )
        else:
            values = _unpack_from(prefix + "IIQQQQQQ", data, position, "ELF program header")
            segment_type, flags, file_offset, file_size = (
                values[0],
                values[1],
                values[2],
                values[5],
            )
        if segment_type == _ELF_PT_LOAD and flags & _ELF_PF_EXECUTE:
            regions.append((file_offset, file_size))
    return tuple(regions)


def _elf_architecture(machine: int) -> BinaryArchitecture:
    if machine == 3:
        return BinaryArchitecture.X86
    if machine == 62:
        return BinaryArchitecture.X86_64
    raise BinaryInspectionError(
        "unsupported_architecture",
        "ELF machine is outside the x86/x64 analysis scope",
        details={"machine": machine},
    )


def _elf_image_base(
    data: bytes,
    *,
    bits: int,
    prefix: str,
    offset: int,
    entry_size: int,
    count: int,
    expected_size: int,
) -> int:
    if count == 0:
        return 0
    _validate_table(data, offset, entry_size, count, expected_size, "ELF program header")
    bases: list[int] = []
    for index in range(count):
        position = offset + index * entry_size
        if bits == 32:
            values = _unpack_from(prefix + "IIIIIIII", data, position, "ELF program header")
            segment_type, file_offset, virtual_address = values[0], values[1], values[2]
        else:
            values = _unpack_from(prefix + "IIQQQQQQ", data, position, "ELF program header")
            segment_type, file_offset, virtual_address = values[0], values[2], values[3]
        if segment_type == _ELF_PT_LOAD and virtual_address >= file_offset:
            bases.append(virtual_address - file_offset)
    return min(bases, default=0)


def _elf_sections(
    data: bytes,
    *,
    bits: int,
    prefix: str,
    offset: int,
    entry_size: int,
    count: int,
    string_index: int,
    expected_size: int,
    limit: int,
) -> tuple[BinarySection, ...]:
    if count == 0:
        return ()
    if count > limit:
        raise BinaryInspectionError(
            "too_many_sections",
            "ELF section count exceeds the configured limit",
            details={"section_count": count, "max_sections": limit},
        )
    _validate_table(data, offset, entry_size, count, expected_size, "ELF section header")
    raw_sections: list[tuple[int, int, int, int, int, int, int]] = []
    for index in range(count):
        position = offset + index * entry_size
        if bits == 32:
            values = _unpack_from(prefix + "IIIIIIIIII", data, position, "ELF section header")
            name, section_type, flags, address, file_offset, size = (
                values[0],
                values[1],
                values[2],
                values[3],
                values[4],
                values[5],
            )
        else:
            values = _unpack_from(prefix + "IIQQQQIIQQ", data, position, "ELF section header")
            name, section_type, flags, address, file_offset, size = (
                values[0],
                values[1],
                values[2],
                values[3],
                values[4],
                values[5],
            )
        raw_sections.append((name, section_type, flags, address, file_offset, size, index))
    names = b""
    if 0 <= string_index < len(raw_sections):
        _, _, _, _, names_offset, names_size, _ = raw_sections[string_index]
        names = _slice(data, names_offset, names_size, "ELF section name table")
    sections: list[BinarySection] = []
    for name_offset, section_type, flags, address, file_offset, size, index in raw_sections:
        if index == 0:
            continue
        name = _terminated_text(names, name_offset) or f"section_{index}"
        file_size = 0 if section_type == _ELF_SHT_NOBITS else size
        _slice(data, file_offset, file_size, f"ELF section {name}")
        sections.append(
            BinarySection(
                name=name,
                virtual_address=address,
                virtual_size=size,
                file_offset=file_offset,
                file_size=file_size,
                readable=bool(flags & _ELF_SHF_ALLOC),
                writable=bool(flags & _ELF_SHF_WRITE),
                executable=bool(flags & _ELF_SHF_EXECINSTR),
            )
        )
    return tuple(sections)


def _inspect_pe(
    data: bytes, limits: BinaryAnalysisLimits
) -> tuple[BinaryMetadata, _ContainerLayout]:
    if len(data) < 0x40:
        raise BinaryInspectionError("truncated_pe", "DOS header is truncated")
    pe_offset = _unpack_from("<I", data, 0x3C, "DOS header")[0]
    if pe_offset < 0x40 or pe_offset + 24 > len(data):
        raise BinaryInspectionError("invalid_pe_offset", "PE header offset is outside the file")
    if data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise BinaryInspectionError("invalid_pe_signature", "PE signature is missing")
    coff = _unpack_from("<HHIIIHH", data, pe_offset + 4, "PE COFF header")
    machine, section_count, optional_size = coff[0], coff[1], coff[5]
    architecture = _pe_architecture(machine)
    if section_count > limits.max_sections:
        raise BinaryInspectionError(
            "too_many_sections",
            "PE section count exceeds the configured limit",
            details={"section_count": section_count, "max_sections": limits.max_sections},
        )
    optional_offset = pe_offset + 24
    optional = _slice(data, optional_offset, optional_size, "PE optional header")
    if len(optional) < 32:
        raise BinaryInspectionError(
            "truncated_pe_optional_header", "PE optional header is truncated"
        )
    magic = struct.unpack_from("<H", optional, 0)[0]
    if magic == 0x10B:
        bits = 32
        if len(optional) < 32:
            raise BinaryInspectionError("truncated_pe_optional_header", "PE32 header is truncated")
        entry_rva = struct.unpack_from("<I", optional, 16)[0]
        image_base = struct.unpack_from("<I", optional, 28)[0]
    elif magic == 0x20B:
        bits = 64
        if len(optional) < 32:
            raise BinaryInspectionError("truncated_pe_optional_header", "PE32+ header is truncated")
        entry_rva = struct.unpack_from("<I", optional, 16)[0]
        image_base = struct.unpack_from("<Q", optional, 24)[0]
    else:
        raise BinaryInspectionError(
            "unsupported_pe_optional_header", "PE optional header is unsupported"
        )
    if (bits == 32 and architecture is not BinaryArchitecture.X86) or (
        bits == 64 and architecture is not BinaryArchitecture.X86_64
    ):
        raise BinaryInspectionError(
            "pe_architecture_mismatch", "PE machine and optional header disagree"
        )
    section_offset = optional_offset + optional_size
    _validate_table(data, section_offset, 40, section_count, 40, "PE section header")
    sections: list[BinarySection] = []
    executable_regions: list[tuple[int, int]] = []
    for index in range(section_count):
        position = section_offset + index * 40
        name = data[position : position + 8].split(b"\0", 1)[0].decode("ascii", "replace")
        if not name:
            name = f"section_{index}"
        virtual_size, virtual_rva, raw_size, raw_offset = struct.unpack_from(
            "<IIII", data, position + 8
        )
        characteristics = struct.unpack_from("<I", data, position + 36)[0]
        _slice(data, raw_offset, raw_size, f"PE section {name}")
        if characteristics & _PE_MEM_EXECUTE:
            executable_regions.append((raw_offset, raw_size))
        sections.append(
            BinarySection(
                name=name,
                virtual_address=image_base + virtual_rva,
                virtual_size=virtual_size,
                file_offset=raw_offset,
                file_size=raw_size,
                readable=bool(characteristics & _PE_MEM_READ),
                writable=bool(characteristics & _PE_MEM_WRITE),
                executable=bool(characteristics & _PE_MEM_EXECUTE),
            )
        )
    return (
        BinaryMetadata(
            format=BinaryFormat.PE,
            architecture=architecture,
            bits=bits,
            endianness="little",
            image_base=image_base,
            entry_point=image_base + entry_rva,
            sections=tuple(sections),
        ),
        _ContainerLayout(
            declared_sections=section_count,
            # PE has no program header table; structure-based packing signals do
            # not apply, so the heuristic falls back to segment entropy alone.
            declared_program_headers=0,
            executable_regions=tuple(executable_regions),
        ),
    )


def _pe_architecture(machine: int) -> BinaryArchitecture:
    if machine == 0x14C:
        return BinaryArchitecture.X86
    if machine == 0x8664:
        return BinaryArchitecture.X86_64
    raise BinaryInspectionError(
        "unsupported_architecture",
        "PE machine is outside the x86/x64 analysis scope",
        details={"machine": machine},
    )


def _ascii_strings(
    data: bytes, metadata: BinaryMetadata, limits: BinaryAnalysisLimits
) -> list[BinaryString]:
    records: list[BinaryString] = []
    start: int | None = None
    for index, value in enumerate(data + b"\0"):
        if 0x20 <= value <= 0x7E or value in (9,):
            if start is None:
                start = index
            continue
        if start is not None and index - start >= limits.min_string_chars:
            raw = data[start:index][: limits.max_string_chars]
            records.append(
                BinaryString(
                    value=raw.decode("ascii", "replace"),
                    encoding="ascii",
                    file_offset=start,
                    virtual_address=metadata.offset_to_virtual_address(start),
                )
            )
            if len(records) >= limits.max_strings:
                break
        start = None
    return records


def _utf16le_strings(
    data: bytes,
    metadata: BinaryMetadata,
    limits: BinaryAnalysisLimits,
    remaining: int,
) -> list[BinaryString]:
    records: list[BinaryString] = []
    index = 0
    while index + 1 < len(data) and len(records) < remaining:
        start = index
        chars: list[int] = []
        while index + 1 < len(data):
            low, high = data[index], data[index + 1]
            if high != 0 or not (0x20 <= low <= 0x7E):
                break
            chars.append(low)
            index += 2
            if len(chars) >= limits.max_string_chars:
                break
        if len(chars) >= limits.min_string_chars:
            records.append(
                BinaryString(
                    value=bytes(chars).decode("ascii"),
                    encoding="utf-16le",
                    file_offset=start,
                    virtual_address=metadata.offset_to_virtual_address(start),
                )
            )
        index = max(index + 2, start + 2)
    return records


def _packer_from_sections(sections: tuple[BinarySection, ...]) -> str | None:
    names = {section["name"].lower() for section in sections}
    if any(name.startswith("upx") for name in names):
        return "UPX"
    if ".aspack" in names:
        return "ASPack"
    if ".themida" in names or ".winlice" in names:
        return "Themida"
    return None


def _heuristic_packed(data: bytes, layout: _ContainerLayout) -> bool:
    """Decide "packed" from container structure and entropy, without naming the shell.

    `_packer_from_sections` only sees packers that leave a tell-tale section
    name, and a packed ELF frequently has no section table for it to read.  Both
    rules below are calibrated against measured populations rather than guessed:

    * entropy >= 7.5 -- an encrypted body.  Ordinary toolchain output stays well
      below this (highest observed over 907 system ELF objects: 6.817).
    * a rebuilt container (no section table, at most five program headers) whose
      executable segment also reaches 7.0, which is how UPX presents on
      linux/amd64 (measured: 7.26 entropy, 0 sections, 3 program headers).

    Requiring the structural signal as well as the entropy keeps size-only
    strippers (`sstrip`) and SIMD-heavy codecs out of the result.  A packer that
    leaves the section table intact *and* compresses below 7.0 is not caught
    here; DIE and the UPX probe are the tools for that case.
    """
    entropy = max(
        (
            _entropy(data[offset : offset + size])
            for offset, size in layout.executable_regions
            if size >= _MIN_ENTROPY_BYTES
        ),
        default=0.0,
    )
    if entropy >= _ENTROPY_ENCRYPTED:
        return True
    stripped_container = (
        layout.declared_sections == 0
        and 0 < layout.declared_program_headers <= _MAX_PACKED_PROGRAM_HEADERS
    )
    return stripped_container and entropy >= _ENTROPY_PACKED


def _entropy(chunk: bytes) -> float:
    """Shannon entropy of a byte string in bits per byte; 0.0 when empty."""
    if not chunk:
        return 0.0
    counts = [0] * 256
    for value in chunk:
        counts[value] += 1
    total = len(chunk)
    return -sum((count / total) * math.log2(count / total) for count in counts if count)


def _validate_table(
    data: bytes, offset: int, entry_size: int, count: int, minimum_size: int, label: str
) -> None:
    if entry_size < minimum_size:
        raise BinaryInspectionError("invalid_table_entry_size", f"{label} entry is too small")
    if offset < 0 or count < 0 or offset > len(data):
        raise BinaryInspectionError("invalid_table_bounds", f"{label} is outside the file")
    total = entry_size * count
    if total > len(data) - offset:
        raise BinaryInspectionError("truncated_table", f"{label} table is truncated")


def _unpack_from(format_string: str, data: bytes, offset: int, label: str) -> tuple[int, ...]:
    size = struct.calcsize(format_string)
    if offset < 0 or offset + size > len(data):
        raise BinaryInspectionError("truncated_structure", f"{label} is truncated")
    return tuple(int(value) for value in struct.unpack_from(format_string, data, offset))


def _slice(data: bytes, offset: int, size: int, label: str) -> bytes:
    if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
        raise BinaryInspectionError("invalid_range", f"{label} range is outside the file")
    return data[offset : offset + size]


def _terminated_text(data: bytes, offset: int) -> str:
    if offset < 0 or offset >= len(data):
        return ""
    end = data.find(b"\0", offset)
    if end < 0:
        end = len(data)
    return data[offset:end].decode("utf-8", "replace")
