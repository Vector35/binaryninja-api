#!/usr/bin/env python3
"""Generate a minimal PE32 image with a legacy /DEBUGTYPE:COFF table."""

import argparse
import struct
from pathlib import Path


FILE_ALIGNMENT = 0x200
SECTION_ALIGNMENT = 0x1000
IMAGE_BASE = 0x400000

PE_OFFSET = 0x80
TEXT_RVA = 0x1000
TEXT_RAW_OFFSET = 0x200
TEXT_RAW_SIZE = 0x1200
TARGET_RVA = 0x1010

RDATA_RVA = 0x3000
RDATA_RAW_OFFSET = 0x1400
RDATA_RAW_SIZE = 0x200

DEBUG_DIRECTORY_RVA = RDATA_RVA
DEBUG_DIRECTORY_SIZE = 28
COFF_DEBUG_OFFSET = 0x1600
COFF_HEADER_SIZE = 32
COFF_SYMBOL_OFFSET = COFF_DEBUG_OFFSET + COFF_HEADER_SIZE
COFF_SYMBOL_COUNT = 1
COFF_SYMBOL_SIZE = 18
COFF_STRING_TABLE_SIZE = 4
COFF_DEBUG_SIZE = COFF_HEADER_SIZE + COFF_SYMBOL_SIZE + COFF_STRING_TABLE_SIZE
FILE_SIZE = COFF_DEBUG_OFFSET + COFF_DEBUG_SIZE


def write_section_header(
    image,
    offset,
    name,
    virtual_size,
    virtual_address,
    raw_size,
    raw_offset,
    characteristics,
):
    struct.pack_into(
        "<8sIIIIIIHHI",
        image,
        offset,
        name.encode("ascii").ljust(8, b"\0"),
        virtual_size,
        virtual_address,
        raw_size,
        raw_offset,
        0,
        0,
        0,
        0,
        characteristics,
    )


def build_image():
    image = bytearray(FILE_SIZE)

    image[0:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, PE_OFFSET)

    # PE signature and IMAGE_FILE_HEADER.
    image[PE_OFFSET : PE_OFFSET + 4] = b"PE\0\0"
    coff_offset = PE_OFFSET + 4
    struct.pack_into(
        "<HHIIIHH",
        image,
        coff_offset,
        0x14C,  # IMAGE_FILE_MACHINE_I386
        2,
        0,
        COFF_SYMBOL_OFFSET,
        COFF_SYMBOL_COUNT,
        0xE0,
        0x0103,  # executable, relocations stripped, 32-bit
    )

    # IMAGE_OPTIONAL_HEADER32 through NumberOfRvaAndSizes.
    optional_offset = coff_offset + 20
    struct.pack_into(
        "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
        image,
        optional_offset,
        0x10B,
        6,
        0,
        TEXT_RAW_SIZE,
        RDATA_RAW_SIZE,
        0,
        TARGET_RVA,
        TEXT_RVA,
        RDATA_RVA,
        IMAGE_BASE,
        SECTION_ALIGNMENT,
        FILE_ALIGNMENT,
        4,
        0,
        0,
        0,
        4,
        0,
        0,
        0x4000,
        FILE_ALIGNMENT,
        0,
        3,  # IMAGE_SUBSYSTEM_WINDOWS_CUI
        0,
        0x100000,
        0x1000,
        0x100000,
        0x1000,
        0,
        16,
    )

    directories_offset = optional_offset + 96
    struct.pack_into(
        "<II",
        image,
        directories_offset + 6 * 8,
        DEBUG_DIRECTORY_RVA,
        DEBUG_DIRECTORY_SIZE,
    )

    section_offset = optional_offset + 0xE0
    write_section_header(
        image,
        section_offset,
        ".text",
        0x1100,
        TEXT_RVA,
        TEXT_RAW_SIZE,
        TEXT_RAW_OFFSET,
        0x60000020,  # code, execute, read
    )
    write_section_header(
        image,
        section_offset + 40,
        ".rdata",
        DEBUG_DIRECTORY_SIZE,
        RDATA_RVA,
        RDATA_RAW_SIZE,
        RDATA_RAW_OFFSET,
        0x40000040,  # initialized data, read
    )

    # mov eax, 42; ret
    target_offset = TEXT_RAW_OFFSET + TARGET_RVA - TEXT_RVA
    image[target_offset : target_offset + 6] = b"\xB8\x2A\x00\x00\x00\xC3"

    # IMAGE_DEBUG_DIRECTORY. The payload is deliberately raw-only.
    struct.pack_into(
        "<IIHHIIII",
        image,
        RDATA_RAW_OFFSET,
        0,
        0,
        0,
        0,
        1,  # IMAGE_DEBUG_TYPE_COFF
        COFF_DEBUG_SIZE,
        0,  # AddressOfRawData
        COFF_DEBUG_OFFSET,
    )

    # IMAGE_COFF_SYMBOLS_HEADER.
    struct.pack_into(
        "<IIIIIIII",
        image,
        COFF_DEBUG_OFFSET,
        COFF_SYMBOL_COUNT,
        COFF_HEADER_SIZE,
        0,
        0,
        TEXT_RVA,
        TEXT_RVA + 0x1100,
        0,
        0,
    )

    # IMAGE_SYMBOL.Value is already an RVA. Adding .text's RVA again produces
    # the incorrect address 0x402010 instead of 0x401010.
    struct.pack_into(
        "<8sIhHBB",
        image,
        COFF_SYMBOL_OFFSET,
        b"legacy\0\0",
        TARGET_RVA,
        1,
        0x20,  # IMAGE_SYM_DTYPE_FUNCTION
        2,  # IMAGE_SYM_CLASS_EXTERNAL
        0,
    )
    struct.pack_into(
        "<I",
        image,
        COFF_SYMBOL_OFFSET + COFF_SYMBOL_SIZE,
        COFF_STRING_TABLE_SIZE,
    )

    return image


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.write_bytes(build_image())


if __name__ == "__main__":
    main()
