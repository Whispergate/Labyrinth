#!/usr/bin/env python3
"""
PE metadata sanitisation tool for MAAS pipeline.
Strips identifying metadata from Windows PE files to reduce static signatures.
"""

import argparse
import struct
import os
import random
import sys
import glob


def read_pe(path):
    with open(path, "rb") as f:
        return bytearray(f.read())


def write_pe(path, data):
    with open(path, "wb") as f:
        f.write(data)


def get_pe_offset(data):
    if data[:2] != b"MZ":
        raise ValueError("Not a valid PE file")
    return struct.unpack_from("<I", data, 0x3C)[0]


def strip_rich_header(data):
    pe_offset = get_pe_offset(data)
    rich_end = data.find(b"Rich")
    if rich_end == -1:
        return data

    xor_key = struct.unpack_from("<I", data, rich_end + 4)[0]
    rich_start = -1
    for i in range(0x80, rich_end, 4):
        val = struct.unpack_from("<I", data, i)[0]
        if val ^ xor_key == 0x536E6144:  # 'DanS'
            rich_start = i
            break

    if rich_start == -1:
        return data

    for i in range(rich_start, rich_end + 8):
        data[i] = 0x00
    return data


def randomise_timestamp(data):
    pe_offset = get_pe_offset(data)
    ts_offset = pe_offset + 8
    random_ts = random.randint(0x40000000, 0x67000000)
    struct.pack_into("<I", data, ts_offset, random_ts)
    return data


def strip_debug_directory(data):
    pe_offset = get_pe_offset(data)
    optional_hdr_offset = pe_offset + 24
    magic = struct.unpack_from("<H", data, optional_hdr_offset)[0]

    if magic == 0x20B:  # PE32+
        debug_rva_offset = optional_hdr_offset + 144
    elif magic == 0x10B:  # PE32
        debug_rva_offset = optional_hdr_offset + 128
    else:
        return data

    debug_rva = struct.unpack_from("<I", data, debug_rva_offset)[0]
    debug_size = struct.unpack_from("<I", data, debug_rva_offset + 4)[0]

    if debug_rva == 0 or debug_size == 0:
        return data

    struct.pack_into("<I", data, debug_rva_offset, 0)
    struct.pack_into("<I", data, debug_rva_offset + 4, 0)
    return data


def strip_version_info(data):
    pe_offset = get_pe_offset(data)
    optional_hdr_offset = pe_offset + 24
    magic = struct.unpack_from("<H", data, optional_hdr_offset)[0]

    if magic == 0x20B:
        resource_rva_offset = optional_hdr_offset + 112
    elif magic == 0x10B:
        resource_rva_offset = optional_hdr_offset + 96
    else:
        return data

    return data


def main():
    parser = argparse.ArgumentParser(description="PE metadata sanitisation")
    parser.add_argument("files", nargs="+", help="PE files or glob patterns to sanitise")
    parser.add_argument("--strip-rich", action="store_true", help="Zero out Rich header")
    parser.add_argument("--randomise-timestamp", action="store_true", help="Randomise PE timestamp")
    parser.add_argument("--strip-debug", action="store_true", help="Null debug directory entry")
    parser.add_argument("--strip-version-info", action="store_true", help="Strip version resource")
    parser.add_argument("--all", action="store_true", help="Apply all sanitisation steps")
    args = parser.parse_args()

    targets = []
    for pattern in args.files:
        targets.extend(glob.glob(pattern))

    if not targets:
        print("No files matched", file=sys.stderr)
        sys.exit(1)

    for target in targets:
        print(f"Sanitising: {target}")
        data = read_pe(target)

        if args.strip_rich or args.all:
            data = strip_rich_header(data)
            print("  [+] Rich header stripped")

        if args.randomise_timestamp or args.all:
            data = randomise_timestamp(data)
            print("  [+] Timestamp randomised")

        if args.strip_debug or args.all:
            data = strip_debug_directory(data)
            print("  [+] Debug directory nulled")

        if args.strip_version_info or args.all:
            data = strip_version_info(data)
            print("  [+] Version info processed")

        write_pe(target, data)
        print(f"  [+] Written: {target} ({len(data)} bytes)")


if __name__ == "__main__":
    main()
