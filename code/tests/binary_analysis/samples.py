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
