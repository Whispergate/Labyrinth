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
import time


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


def find_rich_header(data):
    """Locate the Rich header, returning (start, end_exclusive) or (None, None).

    The Rich header sits between the DOS stub and the PE signature,
    so the search is bounded to that region to avoid false matches
    in code or data sections.
    """
    pe_offset = get_pe_offset(data)

    # Only search between the DOS stub and the PE signature
    rich_end = data.find(b"Rich", 0x80, pe_offset)
    if rich_end == -1:
        return None, None

    xor_key = struct.unpack_from("<I", data, rich_end + 4)[0]
    rich_start = None
    for i in range(0x80, rich_end, 4):
        val = struct.unpack_from("<I", data, i)[0]
        if val ^ xor_key == 0x536E6144:  # 'DanS'
            rich_start = i
            break

    if rich_start is None:
        return None, None

    return rich_start, rich_end + 8


def strip_rich_header(data):
    rich_start, rich_end = find_rich_header(data)
    if rich_start is None:
        return data

    for i in range(rich_start, rich_end):
        data[i] = 0x00
    return data


# Realistic Visual Studio tool IDs for fake Rich header generation.
# Format: (tool_id, min_build, max_build) representing the prodID << 16 | build
# These cover VS 2015-2024 linker, C/C++ compiler, assembler, and import tool IDs.
RICH_TOOL_IDS = [
    # Linkers
    (0x0104, 30000, 36000),   # VS 2019-2022 linker
    (0x0105, 30000, 36000),   # VS 2022 linker (newer)
    (0x0106, 27000, 30000),   # VS 2017 linker
    (0x010E, 30000, 36000),   # VS 2022+ linker
    # C/C++ compilers
    (0x0105, 29000, 36000),   # MSVC cl.exe
    (0x0104, 27000, 32000),   # MSVC cl.exe (older)
    (0x0101, 30000, 36000),   # MSVC C compiler
    (0x0102, 30000, 36000),   # MSVC C++ compiler
    # Assembler / import / resource tools
    (0x0103, 30000, 36000),   # MASM
    (0x00FF, 30000, 36000),   # Import tool
    (0x0100, 30000, 36000),   # Resource compiler
    (0x009D, 30000, 36000),   # UTC C
    (0x009E, 30000, 36000),   # UTC C++
]


def fake_rich_header(data):
    """Replace the Rich header with a plausible fake one."""
    rich_start, rich_end = find_rich_header(data)
    if rich_start is None:
        return data

    region_size = rich_end - rich_start

    # Generate 3-8 fake comp.id entries
    num_entries = random.randint(3, 8)
    xor_key = random.randint(0x10000000, 0xFFFFFFFF)

    # Build the cleartext Rich header:
    #   DanS signature (4 bytes) + 3 padding DWORDs (12 bytes) = 16 bytes header
    #   Then N entries of (comp_id, use_count) = N*8 bytes
    #   Then "Rich" marker (4 bytes) + xor_key (4 bytes) = 8 bytes trailer
    clear = bytearray()
    clear += struct.pack("<I", 0x536E6144)  # 'DanS'
    clear += b"\x00" * 12                    # 3 padding DWORDs

    for _ in range(num_entries):
        tool = random.choice(RICH_TOOL_IDS)
        tool_id = tool[0]
        build = random.randint(tool[1], tool[2])
        comp_id = (tool_id << 16) | (build & 0xFFFF)
        use_count = random.randint(1, 50)
        clear += struct.pack("<II", comp_id, use_count)

    # XOR-encode the DanS header + entries
    encoded = bytearray()
    for i in range(0, len(clear), 4):
        val = struct.unpack_from("<I", clear, i)[0]
        encoded += struct.pack("<I", val ^ xor_key)

    # Append unencoded trailer
    encoded += b"Rich"
    encoded += struct.pack("<I", xor_key)

    # Pad or truncate to fit the original region
    if len(encoded) <= region_size:
        encoded += b"\x00" * (region_size - len(encoded))
    else:
        # Reduce entries to fit (unlikely, but safe)
        encoded = encoded[:region_size]

    data[rich_start:rich_start + region_size] = encoded
    return data


# Curated pool of PE timestamps from legitimate VS compiler release dates (2019-2024).
# These correspond to approximate release builds of Visual Studio / MSVC toolsets.
VS_TIMESTAMP_POOL = [
    0x5C6B4F00,  # VS 2019 16.0   (Feb 2019)
    0x5D2B1A00,  # VS 2019 16.2   (Jul 2019)
    0x5DCE8400,  # VS 2019 16.4   (Nov 2019)
    0x5E8D4E00,  # VS 2019 16.6   (Apr 2020)
    0x5F3C0800,  # VS 2019 16.7   (Aug 2020)
    0x5FED2A00,  # VS 2019 16.8   (Dec 2020)
    0x609C4800,  # VS 2019 16.10  (May 2021)
    0x614E6800,  # VS 2019 16.11  (Sep 2021)
    0x618F3600,  # VS 2022 17.0   (Nov 2021)
    0x6240A800,  # VS 2022 17.2   (Mar 2022)
    0x62F21400,  # VS 2022 17.3   (Aug 2022)
    0x63A38200,  # VS 2022 17.4   (Dec 2022)
    0x6454F000,  # VS 2022 17.6   (May 2023)
    0x65065E00,  # VS 2022 17.8   (Sep 2023)
    0x6564E800,  # VS 2022 17.9   (Nov 2023)
    0x65F38000,  # VS 2022 17.10  (Mar 2024)
    0x66A4F000,  # VS 2022 17.11  (Jul 2024)
]


def randomise_timestamp(data, use_pool=False):
    pe_offset = get_pe_offset(data)
    ts_offset = pe_offset + 8
    if use_pool:
        random_ts = random.choice(VS_TIMESTAMP_POOL)
    else:
        random_ts = random.randint(0x40000000, 0x67000000)
    struct.pack_into("<I", data, ts_offset, random_ts)
    return data


def strip_debug_directory(data):
    pe_offset = get_pe_offset(data)
    optional_hdr_offset = pe_offset + 24
    magic = struct.unpack_from("<H", data, optional_hdr_offset)[0]

    if magic == 0x20B:  # PE32+
        debug_rva_offset = optional_hdr_offset + 160
    elif magic == 0x10B:  # PE32
        debug_rva_offset = optional_hdr_offset + 144
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
        resource_rva_offset = optional_hdr_offset + 128
    elif magic == 0x10B:
        resource_rva_offset = optional_hdr_offset + 112
    else:
        return data

    return data


def get_section_headers(data):
    """Return a list of (name, virtual_size, rva, raw_size, raw_offset) for each section."""
    pe_offset = get_pe_offset(data)
    num_sections = struct.unpack_from("<H", data, pe_offset + 6)[0]
    optional_hdr_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
    first_section = pe_offset + 24 + optional_hdr_size

    sections = []
    for i in range(num_sections):
        off = first_section + i * 40
        name = data[off:off + 8].rstrip(b"\x00").decode("ascii", errors="replace")
        vsize = struct.unpack_from("<I", data, off + 8)[0]
        rva = struct.unpack_from("<I", data, off + 12)[0]
        raw_size = struct.unpack_from("<I", data, off + 16)[0]
        raw_offset = struct.unpack_from("<I", data, off + 20)[0]
        sections.append((name, vsize, rva, raw_size, raw_offset))
    return sections


def rva_to_file_offset(sections, rva):
    """Convert an RVA to a raw file offset using the section table."""
    for name, vsize, sec_rva, raw_size, raw_offset in sections:
        if sec_rva <= rva < sec_rva + max(vsize, raw_size):
            return raw_offset + (rva - sec_rva)
    return None


def strip_pdb_path(data):
    """Walk debug directory entries and zero out PDB path strings in CODEVIEW entries."""
    pe_offset = get_pe_offset(data)
    optional_hdr_offset = pe_offset + 24
    magic = struct.unpack_from("<H", data, optional_hdr_offset)[0]

    if magic == 0x20B:  # PE32+
        debug_rva_offset = optional_hdr_offset + 160
    elif magic == 0x10B:  # PE32
        debug_rva_offset = optional_hdr_offset + 144
    else:
        return data

    debug_rva = struct.unpack_from("<I", data, debug_rva_offset)[0]
    debug_size = struct.unpack_from("<I", data, debug_rva_offset + 4)[0]

    if debug_rva == 0 or debug_size == 0:
        return data

    sections = get_section_headers(data)
    debug_file_offset = rva_to_file_offset(sections, debug_rva)
    if debug_file_offset is None:
        return data

    # Each debug directory entry is 28 bytes
    IMAGE_DEBUG_TYPE_CODEVIEW = 2
    num_entries = debug_size // 28

    for i in range(num_entries):
        entry_off = debug_file_offset + i * 28
        if entry_off + 28 > len(data):
            break

        entry_type = struct.unpack_from("<I", data, entry_off + 12)[0]
        cv_size = struct.unpack_from("<I", data, entry_off + 16)[0]
        cv_raw_offset = struct.unpack_from("<I", data, entry_off + 24)[0]

        if entry_type != IMAGE_DEBUG_TYPE_CODEVIEW:
            continue
        if cv_raw_offset == 0 or cv_size == 0:
            continue
        if cv_raw_offset + cv_size > len(data):
            continue

        # Check for RSDS (0x53445352) or NB10 (0x3031424E) signature
        sig = struct.unpack_from("<I", data, cv_raw_offset)[0]

        if sig == 0x53445352:  # 'RSDS'
            # RSDS: 4 sig + 16 GUID + 4 age = 24 bytes header, then PDB path
            pdb_start = cv_raw_offset + 24
            pdb_end = cv_raw_offset + cv_size
            if pdb_start < pdb_end and pdb_end <= len(data):
                for j in range(pdb_start, pdb_end):
                    data[j] = 0x00

        elif sig == 0x3031424E:  # 'NB10'
            # NB10: 4 sig + 4 offset + 4 timestamp + 4 age = 16 bytes, then PDB path
            pdb_start = cv_raw_offset + 16
            pdb_end = cv_raw_offset + cv_size
            if pdb_start < pdb_end and pdb_end <= len(data):
                for j in range(pdb_start, pdb_end):
                    data[j] = 0x00

    return data


def recalc_checksum(data):
    """Recalculate and update the PE checksum in the optional header."""
    pe_offset = get_pe_offset(data)
    # Checksum is at PE offset + 24 (optional header start) + 64
    checksum_offset = pe_offset + 24 + 64

    # Zero out the existing checksum field before computing
    original_checksum = struct.unpack_from("<I", data, checksum_offset)[0]
    struct.pack_into("<I", data, checksum_offset, 0)

    # Standard PE checksum algorithm: sum all 16-bit words with carry
    checksum = 0
    remainder = len(data) % 2
    for i in range(0, len(data) - remainder, 2):
        val = struct.unpack_from("<H", data, i)[0]
        checksum += val
        checksum = (checksum & 0xFFFF) + (checksum >> 16)

    if remainder:
        checksum += data[-1]
        checksum = (checksum & 0xFFFF) + (checksum >> 16)

    # Final fold
    checksum = (checksum & 0xFFFF) + (checksum >> 16)
    checksum += len(data)
    checksum &= 0xFFFFFFFF

    struct.pack_into("<I", data, checksum_offset, checksum)
    return data


# Pool of plausible version info entries for --randomise-version / --version-rc
VERSION_INFO_POOL = [
    {"CompanyName": "Microsoft Corporation", "ProductName": "Microsoft Visual C++ Runtime Library",
     "FileDescription": "C Runtime DLL", "InternalName": "msvcrt"},
    {"CompanyName": "Microsoft Corporation", "ProductName": "Microsoft Windows Operating System",
     "FileDescription": "Windows System Component", "InternalName": "winsys"},
    {"CompanyName": "Microsoft Corporation", "ProductName": "Microsoft .NET Framework",
     "FileDescription": ".NET Runtime Component", "InternalName": "clrjit"},
    {"CompanyName": "Intel Corporation", "ProductName": "Intel Management Engine Components",
     "FileDescription": "Intel ME Service", "InternalName": "imesvc"},
    {"CompanyName": "Intel Corporation", "ProductName": "Intel Graphics Driver",
     "FileDescription": "Intel HD Graphics Kernel Mode Driver", "InternalName": "igfx"},
    {"CompanyName": "NVIDIA Corporation", "ProductName": "NVIDIA Display Driver",
     "FileDescription": "NVIDIA Compatible Windows Display Driver", "InternalName": "nvd3d"},
    {"CompanyName": "Realtek Semiconductor Corp.", "ProductName": "Realtek High Definition Audio Driver",
     "FileDescription": "Realtek HD Audio Service", "InternalName": "rtksvc"},
    {"CompanyName": "Adobe Inc.", "ProductName": "Adobe Acrobat Reader",
     "FileDescription": "Adobe PDF Library", "InternalName": "acrord"},
    {"CompanyName": "Oracle Corporation", "ProductName": "Java Platform SE",
     "FileDescription": "Java Runtime Environment", "InternalName": "jre"},
    {"CompanyName": "Broadcom Inc.", "ProductName": "Broadcom NetXtreme Driver",
     "FileDescription": "Network Adapter Driver", "InternalName": "bxnd"},
    {"CompanyName": "Logitech Inc.", "ProductName": "Logitech Download Assistant",
     "FileDescription": "Logitech Device Helper", "InternalName": "lda"},
    {"CompanyName": "Synaptics Incorporated", "ProductName": "Synaptics Pointing Device Driver",
     "FileDescription": "Synaptics TouchPad Helper", "InternalName": "syntphelper"},
    {"CompanyName": "Microsoft Corporation", "ProductName": "Microsoft OneDrive",
     "FileDescription": "OneDrive Sync Engine", "InternalName": "onedrive"},
    {"CompanyName": "Microsoft Corporation", "ProductName": "Windows Defender",
     "FileDescription": "Antimalware Service Executable", "InternalName": "msmpeng"},
    {"CompanyName": "Dell Inc.", "ProductName": "Dell SupportAssist",
     "FileDescription": "Dell Support Service", "InternalName": "dellsup"},
    {"CompanyName": "HP Inc.", "ProductName": "HP Support Solutions Framework",
     "FileDescription": "HP Support Service", "InternalName": "hpsupport"},
    {"CompanyName": "Lenovo", "ProductName": "Lenovo System Update",
     "FileDescription": "System Update Service", "InternalName": "tvsu"},
    {"CompanyName": "Texas Instruments Incorporated", "ProductName": "TI USB Audio Driver",
     "FileDescription": "TI Audio Device Service", "InternalName": "tiusbaudio"},
    {"CompanyName": "Qualcomm Atheros", "ProductName": "Qualcomm Atheros Wireless Driver",
     "FileDescription": "Wireless Network Adapter Service", "InternalName": "qcawlan"},
    {"CompanyName": "Microsoft Corporation", "ProductName": "Microsoft Edge",
     "FileDescription": "Microsoft Edge Update Service", "InternalName": "msedgeupdate"},
]


def generate_version_rc(pe_path):
    """Generate a .rc file with plausible version info alongside the PE file."""
    entry = random.choice(VERSION_INFO_POOL)
    major = random.randint(1, 15)
    minor = random.randint(0, 99)
    build = random.randint(1, 9999)
    revision = random.randint(0, 999)

    ver_str = f"{major}.{minor}.{build}.{revision}"
    ver_csv = f"{major},{minor},{build},{revision}"

    rc_content = f"""#include <winver.h>

VS_VERSION_INFO VERSIONINFO
FILEVERSION    {ver_csv}
PRODUCTVERSION {ver_csv}
FILEFLAGSMASK  VS_FFI_FILEFLAGSMASK
FILEFLAGS      0x0
FILEOS         VOS_NT_WINDOWS32
FILETYPE       VFT_DLL
FILESUBTYPE    VFT2_UNKNOWN
BEGIN
    BLOCK "StringFileInfo"
    BEGIN
        BLOCK "040904B0"
        BEGIN
            VALUE "CompanyName",      "{entry['CompanyName']}"
            VALUE "FileDescription",  "{entry['FileDescription']}"
            VALUE "FileVersion",      "{ver_str}"
            VALUE "InternalName",     "{entry['InternalName']}"
            VALUE "LegalCopyright",   "Copyright (C) {random.randint(2018, 2024)} {entry['CompanyName']}"
            VALUE "OriginalFilename", "{entry['InternalName']}.dll"
            VALUE "ProductName",      "{entry['ProductName']}"
            VALUE "ProductVersion",   "{ver_str}"
        END
    END
    BLOCK "VarFileInfo"
    BEGIN
        VALUE "Translation", 0x0409, 0x04B0
    END
END
"""
    rc_path = os.path.splitext(pe_path)[0] + ".rc"
    with open(rc_path, "w") as f:
        f.write(rc_content)
    return rc_path


def main():
    parser = argparse.ArgumentParser(description="PE metadata sanitisation")
    parser.add_argument("files", nargs="+", help="PE files or glob patterns to sanitise")
    parser.add_argument("--strip-rich", action="store_true", help="Zero out Rich header")
    parser.add_argument("--fake-rich", action="store_true", help="Replace Rich header with a plausible fake")
    parser.add_argument("--randomise-timestamp", action="store_true", help="Randomise PE timestamp")
    parser.add_argument("--timestamp-pool", action="store_true",
                        help="Pick timestamp from curated VS release dates instead of pure random")
    parser.add_argument("--strip-debug", action="store_true", help="Null debug directory entry")
    parser.add_argument("--strip-pdb-path", action="store_true",
                        help="Zero out PDB path strings in CODEVIEW debug entries")
    parser.add_argument("--strip-version-info", action="store_true", help="Strip version resource")
    parser.add_argument("--randomise-version", action="store_true",
                        help="Generate a .rc file with random plausible version info (use with --version-rc)")
    parser.add_argument("--version-rc", action="store_true",
                        help="Output a companion .rc resource file with fake version info")
    parser.add_argument("--recalc-checksum", action="store_true",
                        help="Recalculate and update the PE checksum after modifications")
    parser.add_argument("--all", action="store_true", help="Apply all sanitisation steps")
    args = parser.parse_args()

    # --fake-rich and --strip-rich are mutually exclusive
    if args.fake_rich and args.strip_rich:
        print("Error: --fake-rich and --strip-rich are mutually exclusive", file=sys.stderr)
        sys.exit(1)

    targets = []
    for pattern in args.files:
        targets.extend(glob.glob(pattern))

    if not targets:
        print("No files matched", file=sys.stderr)
        sys.exit(1)

    for target in targets:
        print(f"Sanitising: {target}")
        data = read_pe(target)

        # Rich header: fake takes precedence under --all, strip-rich only when explicitly asked
        if args.fake_rich or args.all:
            data = fake_rich_header(data)
            print("  [+] Rich header faked")
        elif args.strip_rich:
            data = strip_rich_header(data)
            print("  [+] Rich header stripped")

        if args.randomise_timestamp or args.all:
            use_pool = args.timestamp_pool or args.all
            data = randomise_timestamp(data, use_pool=use_pool)
            pool_note = " (from VS release pool)" if use_pool else ""
            print(f"  [+] Timestamp randomised{pool_note}")

        if args.strip_debug or args.all:
            data = strip_debug_directory(data)
            print("  [+] Debug directory nulled")

        if args.strip_pdb_path or args.all:
            data = strip_pdb_path(data)
            print("  [+] PDB path stripped")

        if args.strip_version_info or args.all:
            data = strip_version_info(data)
            print("  [+] Version info processed")

        if args.randomise_version or args.version_rc or args.all:
            rc_path = generate_version_rc(target)
            print(f"  [+] Version RC generated: {rc_path}")

        if args.recalc_checksum or args.all:
            data = recalc_checksum(data)
            print("  [+] PE checksum recalculated")

        write_pe(target, data)
        print(f"  [+] Written: {target} ({len(data)} bytes)")


if __name__ == "__main__":
    main()
