from __future__ import annotations

import struct


def elf64_sample(*, machine: int = 62, upx_section: bool = False) -> bytes:
    section_name = b"UPX0" if upx_section else b".text"
    names = b"\0" + section_name + b"\0.shstrtab\0"
    text_name_offset = 1
    string_name_offset = 1 + len(section_name) + 1
    section_headers_offset = 0x80
    text_offset = 0x200
    names_offset = text_offset + 8
    total_size = names_offset + len(names)
    data = bytearray(total_size)
    data[:16] = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\0" * 8
    struct.pack_into(
        "<HHIQQQIHHHHHH",
        data,
        16,
        2,
        machine,
        1,
        0x401000,
        64,
        section_headers_offset,
        0,
        64,
        56,
        1,
        64,
        3,
        2,
    )
    struct.pack_into(
        "<IIQQQQQQ",
        data,
        64,
        1,
        5,
        0,
        0x400000,
        0x400000,
        total_size,
        total_size,
        0x1000,
    )
    struct.pack_into(
        "<IIQQQQIIQQ",
        data,
        section_headers_offset + 64,
        text_name_offset,
        1,
        0x6,
        0x401000,
        text_offset,
        8,
        0,
        0,
        16,
        0,
    )
    struct.pack_into(
        "<IIQQQQIIQQ",
        data,
        section_headers_offset + 128,
        string_name_offset,
        3,
        0,
        0,
        names_offset,
        len(names),
        0,
        0,
        1,
        0,
    )
    data[text_offset : text_offset + 8] = b"\x55\x48\x89\xe5\x90\x5d\xc3\x00"
    data[names_offset : names_offset + len(names)] = names
    return bytes(data)


def packed_elf64_sample(*, keep_sections: bool = False, alphabet: int = 256) -> bytes:
    """Build an ELF shaped like packer output, without relying on section names.

    `alphabet` picks the byte range used to fill the executable segment, which
    sets its entropy exactly: 256 symbols gives 8.0 bits/byte (an encrypted
    body) and 150 gives about 7.23 (a compressed one).  `keep_sections` controls
    whether a section header table survives, which is the difference between the
    entropy-only signal and the entropy-plus-structure one.
    """
    phoff, phnum, phentsize = 64, 3, 56
    shoff, shnum, shentsize = 0x100, (3 if keep_sections else 0), 64
    names = b"\0.text\0.shstrtab\0"
    names_offset = 0x200
    text_offset, text_size = 0x1000, 0x2000
    data = bytearray(text_offset + text_size)
    data[:16] = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\0" * 8
    struct.pack_into(
        "<HHIQQQIHHHHHH",
        data,
        16,
        2,
        62,
        1,
        0x401000,
        phoff,
        (shoff if keep_sections else 0),
        0,
        64,
        phentsize,
        phnum,
        shentsize,
        shnum,
        (2 if keep_sections else 0),
    )
    struct.pack_into("<IIQQQQQQ", data, phoff, 1, 6, 0, 0x400000, 0x400000, 0x1000, 0x1000, 0x1000)
    struct.pack_into(
        "<IIQQQQQQ",
        data,
        phoff + phentsize,
        1,
        5,
        text_offset,
        0x401000,
        0x401000,
        text_size,
        text_size,
        0x1000,
    )
    struct.pack_into(
        "<IIQQQQQQ", data, phoff + 2 * phentsize, 0x6474E551, 6, 0, 0, 0, 0, 0, 0x10
    )
    body = (bytes(range(alphabet)) * (text_size // alphabet + 1))[:text_size]
    data[text_offset : text_offset + text_size] = body
    data[names_offset : names_offset + len(names)] = names
    if keep_sections:
        struct.pack_into(
            "<IIQQQQIIQQ",
            data,
            shoff + shentsize,
            1,
            1,
            0x6,
            0x401000,
            text_offset,
            text_size,
            0,
            0,
            0x1000,
            0,
        )
        struct.pack_into(
            "<IIQQQQIIQQ",
            data,
            shoff + 2 * shentsize,
            7,
            3,
            0,
            0,
            names_offset,
            len(names),
            0,
            0,
            1,
            0,
        )
    return bytes(data)


def pe64_sample(*, machine: int = 0x8664) -> bytes:
    pe_offset = 0x80
    optional_size = 0xF0
    section_offset = pe_offset + 24 + optional_size
    data = bytearray(0x400)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, pe_offset)
    data[pe_offset : pe_offset + 4] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, pe_offset + 4, machine, 1, 0, 0, 0, optional_size, 0x22)
    optional = pe_offset + 24
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<I", data, optional + 16, 0x1000)
    struct.pack_into("<Q", data, optional + 24, 0x140000000)
    data[section_offset : section_offset + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", data, section_offset + 8, 8, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", data, section_offset + 36, 0x60000020)
    data[0x200:0x208] = b"\x55\x48\x89\xe5\x90\x5d\xc3\x00"
    data[0x220:0x22D] = b"hello-binary\0"
    return bytes(data)
