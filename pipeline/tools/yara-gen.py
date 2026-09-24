#!/usr/bin/env python3
"""
Generate YARA rules from own payload artifacts to understand detection surface.

Extracts unique byte patterns from PE files and produces YARA rules that can be
used to:
  - Understand what AV/EDR might be keying on
  - Verify obfuscation effectiveness (negative rules)
  - Track payload signature stability across builds

Usage:
    yara-gen.py --input loader.exe --output loader.yar --name MAAS_Loader_C_OLLVM
    yara-gen.py --input-dir /payloads/latest/ --output-dir /payloads/yara/
    yara-gen.py --input loader.exe --output negative.yar --name PRE_OBFUSC --negative
"""

import argparse
import hashlib
import os
import re
import struct
import sys
from collections import OrderedDict


# ---------------------------------------------------------------------------
# PE parsing utilities
# ---------------------------------------------------------------------------

def read_pe(path):
    """Read a PE file into a bytearray."""
    with open(path, "rb") as f:
        return bytearray(f.read())


def get_pe_offset(data):
    """Return the offset of the PE signature."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError("Not a valid PE file (missing MZ header)")
    return struct.unpack_from("<I", data, 0x3C)[0]


def get_optional_header_info(data):
    """Return (pe_offset, optional_header_offset, magic, is_pe32plus)."""
    pe_off = get_pe_offset(data)
    opt_off = pe_off + 24
    magic = struct.unpack_from("<H", data, opt_off)[0]
    return pe_off, opt_off, magic, (magic == 0x20B)


def get_section_headers(data):
    """Return list of dicts with section metadata."""
    pe_off = get_pe_offset(data)
    num_sections = struct.unpack_from("<H", data, pe_off + 6)[0]
    opt_hdr_size = struct.unpack_from("<H", data, pe_off + 20)[0]
    first_section = pe_off + 24 + opt_hdr_size

    sections = []
    for i in range(num_sections):
        off = first_section + i * 40
        if off + 40 > len(data):
            break
        name_bytes = data[off:off + 8]
        name = name_bytes.rstrip(b"\x00").decode("ascii", errors="replace")
        sections.append({
            "name": name,
            "virtual_size": struct.unpack_from("<I", data, off + 8)[0],
            "rva": struct.unpack_from("<I", data, off + 12)[0],
            "raw_size": struct.unpack_from("<I", data, off + 16)[0],
            "raw_offset": struct.unpack_from("<I", data, off + 20)[0],
            "characteristics": struct.unpack_from("<I", data, off + 36)[0],
        })
    return sections


def rva_to_offset(sections, rva):
    """Convert an RVA to a raw file offset."""
    for sec in sections:
        if sec["rva"] <= rva < sec["rva"] + max(sec["virtual_size"], sec["raw_size"]):
            return sec["raw_offset"] + (rva - sec["rva"])
    return None


# ---------------------------------------------------------------------------
# Import hash (imphash) calculation
# ---------------------------------------------------------------------------

def calculate_imphash(data):
    """
    Calculate the import hash (imphash) of a PE file.

    The imphash is an MD5 of the normalised import table entries,
    following the convention: dll_name.function_name joined by commas.
    """
    try:
        pe_off, opt_off, magic, is_64 = get_optional_header_info(data)
    except (ValueError, struct.error):
        return None

    # Import directory RVA is at different offsets for PE32 vs PE32+
    if is_64:
        import_rva_off = opt_off + 120
    else:
        import_rva_off = opt_off + 104

    if import_rva_off + 8 > len(data):
        return None

    import_rva = struct.unpack_from("<I", data, import_rva_off)[0]
    import_size = struct.unpack_from("<I", data, import_rva_off + 4)[0]

    if import_rva == 0 or import_size == 0:
        return None

    sections = get_section_headers(data)
    import_offset = rva_to_offset(sections, import_rva)
    if import_offset is None:
        return None

    entries = []
    # Each import descriptor is 20 bytes
    pos = import_offset
    while pos + 20 <= len(data):
        ilt_rva = struct.unpack_from("<I", data, pos)[0]
        name_rva = struct.unpack_from("<I", data, pos + 12)[0]

        if name_rva == 0:
            break

        name_off = rva_to_offset(sections, name_rva)
        if name_off is None:
            pos += 20
            continue

        # Read the DLL name (null-terminated ASCII)
        dll_name = ""
        j = name_off
        while j < len(data) and data[j] != 0:
            dll_name += chr(data[j])
            j += 1

        # Strip .dll extension for normalisation
        dll_name_norm = dll_name.lower()
        for ext in (".dll", ".ocx", ".sys"):
            if dll_name_norm.endswith(ext):
                dll_name_norm = dll_name_norm[: -len(ext)]
                break

        # Walk the ILT/IAT to get function names
        lookup_rva = ilt_rva if ilt_rva != 0 else struct.unpack_from("<I", data, pos + 16)[0]
        if lookup_rva == 0:
            pos += 20
            continue

        lookup_off = rva_to_offset(sections, lookup_rva)
        if lookup_off is None:
            pos += 20
            continue

        entry_size = 8 if is_64 else 4
        ordinal_flag = 1 << (63 if is_64 else 31)

        lpos = lookup_off
        while lpos + entry_size <= len(data):
            if is_64:
                val = struct.unpack_from("<Q", data, lpos)[0]
            else:
                val = struct.unpack_from("<I", data, lpos)[0]

            if val == 0:
                break

            if val & ordinal_flag:
                ordinal = val & 0xFFFF
                entries.append(f"{dll_name_norm}.ord{ordinal}")
            else:
                hint_rva = val & 0x7FFFFFFF
                hint_off = rva_to_offset(sections, hint_rva)
                if hint_off is not None and hint_off + 2 < len(data):
                    # Skip 2-byte hint, read function name
                    func_name = ""
                    k = hint_off + 2
                    while k < len(data) and data[k] != 0:
                        func_name += chr(data[k])
                        k += 1
                    entries.append(f"{dll_name_norm}.{func_name.lower()}")

            lpos += entry_size

        pos += 20

    if not entries:
        return None

    return hashlib.md5(",".join(entries).encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Pattern extraction
# ---------------------------------------------------------------------------

def extract_ascii_strings(data, min_len=6, max_len=128):
    """Extract printable ASCII strings from binary data."""
    pattern = re.compile(rb"[\x20-\x7e]{%d,%d}" % (min_len, max_len))
    results = []
    for m in pattern.finditer(bytes(data)):
        s = m.group().decode("ascii")
        results.append((m.start(), s))
    return results


def extract_wide_strings(data, min_len=6, max_len=128):
    """Extract UTF-16LE encoded strings from binary data."""
    results = []
    i = 0
    while i < len(data) - 1:
        chars = []
        start = i
        while i < len(data) - 1:
            lo, hi = data[i], data[i + 1]
            if hi == 0 and 0x20 <= lo <= 0x7E:
                chars.append(chr(lo))
                i += 2
            else:
                break
        if min_len <= len(chars) <= max_len:
            results.append((start, "".join(chars)))
        else:
            i += 2 if not chars else 0
            if not chars:
                i += 2
    return results


def extract_api_strings(data):
    """Extract strings that look like Windows API function names."""
    api_pattern = re.compile(
        rb"(?:Nt|Zw|Rtl|Ldr|Virtual|Heap|Create|Open|Write|Read|Close|"
        rb"Get|Set|Load|Find|Map|Unmap|Alloc|Free|Query|Resume|Suspend|"
        rb"Wait|Signal|Duplicate|Protect|Flush|Process|Thread|Token|"
        rb"Inject|Shell|Execute|Reg|Crypt|Base64|Connect|Socket|Recv|Send|"
        rb"WSA|Http|Internet|Url|Download|WinExec|system|popen|cmd|"
        rb"powershell|wscript|cscript|mshta)[A-Za-z0-9]{2,64}"
    )
    results = []
    for m in api_pattern.finditer(bytes(data)):
        s = m.group().decode("ascii", errors="replace")
        results.append((m.start(), s))
    return results


def extract_rich_header_pattern(data):
    """Extract the Rich header hash pattern if present."""
    rich_end = data.find(b"Rich")
    if rich_end == -1:
        return None

    xor_key = struct.unpack_from("<I", data, rich_end + 4)[0]
    # Search backwards for DanS
    rich_start = None
    for i in range(0x80, rich_end, 4):
        val = struct.unpack_from("<I", data, i)[0]
        if val ^ xor_key == 0x536E6144:
            rich_start = i
            break

    if rich_start is None:
        return None

    # Hash the cleartext Rich header
    cleartext = bytearray()
    for i in range(rich_start, rich_end, 4):
        val = struct.unpack_from("<I", data, i)[0]
        cleartext += struct.pack("<I", val ^ xor_key)

    rich_hash = hashlib.md5(bytes(cleartext)).hexdigest()
    return rich_hash


def extract_section_name_pattern(data):
    """Extract non-standard section names as detection indicators."""
    standard_names = {
        ".text", ".rdata", ".data", ".bss", ".rsrc", ".reloc",
        ".idata", ".edata", ".pdata", ".tls", ".CRT", ".debug",
        ".textbss", ".00cfg",
    }
    sections = get_section_headers(data)
    unusual = []
    for sec in sections:
        name = sec["name"]
        if name and name not in standard_names:
            unusual.append(name)
    return unusual


def find_xor_decrypt_loops(data):
    """
    Locate common XOR decryption loop patterns in x86-64 code.

    Looks for sequences like:
        xor [reg+idx], key_reg; inc/add idx; cmp/loop
    Returns byte patterns around the XOR instruction.
    """
    patterns = []
    # Common XOR loop opcodes: 30 (xor byte), 31 (xor dword), 32, 33
    # We look for xor + increment + compare sequences
    xor_opcodes = [0x30, 0x31, 0x32, 0x33, 0x34, 0x35]

    for i in range(len(data) - 16):
        if data[i] in xor_opcodes:
            # Check if followed within a few bytes by an increment and compare/loop
            window = data[i:i + 16]
            has_inc = any(b in window[2:10] for b in [0xFF, 0x48, 0x41])  # inc variants
            has_cmp = any(b in window[4:14] for b in [0x39, 0x3B, 0x3C, 0x3D, 0x83, 0x81])
            has_jmp = any(b in window[6:16] for b in [0x72, 0x75, 0x76, 0x7C, 0x7E, 0xE2, 0xEB])

            if has_inc and (has_cmp or has_jmp):
                # Extract a meaningful window around the XOR
                start = max(0, i - 2)
                end = min(len(data), i + 12)
                snippet = bytes(data[start:end])
                if len(snippet) >= 8:
                    patterns.append((start, snippet, "XOR decrypt loop candidate"))

    return patterns


def find_syscall_patterns(data):
    """
    Find direct/indirect syscall instruction sequences.

    Looks for:
        mov r10, rcx; mov eax, SSN; syscall
        (4C 8B D1) (B8 xx xx 00 00) (0F 05)
    """
    patterns = []

    # Direct syscall: mov r10,rcx + mov eax,imm32 + syscall
    for i in range(len(data) - 12):
        if (data[i:i + 3] == b"\x4C\x8B\xD1" and      # mov r10, rcx
                data[i + 3] == 0xB8 and                  # mov eax, imm32
                data[i + 8:i + 10] == b"\x0F\x05"):     # syscall
            ssn = struct.unpack_from("<I", data, i + 4)[0]
            snippet = bytes(data[i:i + 10])
            patterns.append((i, snippet, f"Direct syscall (SSN=0x{ssn:X})"))

    # Just the syscall instruction with preceding mov eax
    for i in range(len(data) - 6):
        if data[i:i + 2] == b"\x0F\x05":  # syscall
            # Check if preceded by mov eax
            if i >= 5 and data[i - 5] == 0xB8:
                ssn = struct.unpack_from("<I", data, i - 4)[0]
                if ssn < 0x1000:  # Reasonable SSN range
                    snippet = bytes(data[i - 5:i + 2])
                    patterns.append((i - 5, snippet, f"Syscall stub (SSN=0x{ssn:X})"))

    return patterns


def find_virtualalloc_memcpy_pattern(data):
    """
    Look for call sequences resembling VirtualAlloc + memcpy + execution transfer.

    These are common in shellcode loaders:
        call VirtualAlloc -> copy shellcode -> call/jmp to allocated memory
    """
    patterns = []

    # Look for VirtualAlloc string reference near call instructions
    va_offsets = []
    for m in re.finditer(rb"VirtualAlloc\x00", bytes(data)):
        va_offsets.append(m.start())

    for m in re.finditer(rb"VirtualProtect\x00", bytes(data)):
        va_offsets.append(m.start())

    # Also look for indirect call patterns (call [rip+disp] or call [reg])
    # FF 15 xx xx xx xx = call [rip+disp32]
    for i in range(len(data) - 6):
        if data[i:i + 2] == b"\xFF\x15":
            # This is a call through IAT - common for API calls
            snippet = bytes(data[i:i + 6])
            # Only add if in code section
            if i < len(data) // 2:  # rough heuristic for code section
                patterns.append((i, snippet, "Indirect call (possible API call via IAT)"))
                if len(patterns) > 5:
                    break  # Limit to avoid noise

    return patterns


def extract_pe_patterns(data, args_negative=False):
    """
    Main extraction function. Returns a list of (bytes_pattern, description) tuples.

    If args_negative is True, extracts patterns that SHOULD disappear after
    obfuscation -- useful for verifying obfuscation effectiveness.
    """
    all_patterns = []

    # 1. Rich header hash
    rich_hash = extract_rich_header_pattern(data)
    if rich_hash:
        all_patterns.append(
            (None, f"Rich header hash: {rich_hash}", "rich_header")
        )

    # 2. Import hash
    imphash = calculate_imphash(data)
    if imphash:
        all_patterns.append(
            (None, f"Imphash: {imphash}", "imphash")
        )

    # 3. Section names
    unusual_sections = extract_section_name_pattern(data)
    for name in unusual_sections:
        name_bytes = name.encode("ascii", errors="replace").ljust(8, b"\x00")[:8]
        all_patterns.append(
            (name_bytes, f"Unusual section name: {name}", "section_name")
        )

    # 4. API strings (high signal for detection)
    api_strings = extract_api_strings(data)
    seen_apis = set()
    for offset, api_name in api_strings:
        if api_name not in seen_apis and len(api_name) >= 6:
            seen_apis.add(api_name)
            all_patterns.append(
                (api_name.encode("ascii"), f"API string: {api_name}", "api_string")
            )
            if len(seen_apis) >= 30:
                break

    # 5. Suspicious strings (paths, commands, URLs)
    ascii_strings = extract_ascii_strings(data, min_len=8)
    suspicious_keywords = [
        "ntdll", "kernel32", "advapi32", "shell32", "user32",
        "amsi", "etw", "wldp", "clr", "mscoree",
        "\\pipe\\", "\\\\.", "cmd.exe", "powershell",
        "http://", "https://", "socket", "connect",
        "inject", "shellcode", "payload", "beacon",
        "mimikatz", "cobalt", "meterpreter", "sliver",
    ]

    seen_strings = set()
    for offset, s in ascii_strings:
        s_lower = s.lower()
        if any(kw in s_lower for kw in suspicious_keywords):
            if s not in seen_strings:
                seen_strings.add(s)
                all_patterns.append(
                    (s.encode("ascii"), f"Suspicious string: {s}", "string")
                )
                if len(seen_strings) >= 20:
                    break

    # 6. Wide string API names
    wide_strings = extract_wide_strings(data, min_len=6)
    seen_wide = set()
    for offset, s in wide_strings:
        s_lower = s.lower()
        if any(kw in s_lower for kw in suspicious_keywords):
            if s not in seen_wide:
                seen_wide.add(s)
                # Store as wide-char pattern
                wide_bytes = s.encode("utf-16-le")
                all_patterns.append(
                    (wide_bytes, f"Wide string: {s}", "wide_string")
                )
                if len(seen_wide) >= 10:
                    break

    # 7. Syscall patterns (code-level detection)
    syscall_pats = find_syscall_patterns(data)
    for offset, snippet, desc in syscall_pats:
        all_patterns.append((snippet, desc, "syscall"))

    # 8. XOR decrypt loops
    xor_pats = find_xor_decrypt_loops(data)
    seen_xor = set()
    for offset, snippet, desc in xor_pats:
        sig = snippet[:6]
        if sig not in seen_xor:
            seen_xor.add(sig)
            all_patterns.append((snippet, desc, "xor_loop"))
            if len(seen_xor) >= 5:
                break

    # 9. VirtualAlloc/memcpy patterns
    va_pats = find_virtualalloc_memcpy_pattern(data)
    for offset, snippet, desc in va_pats[:3]:
        all_patterns.append((snippet, desc, "api_call"))

    # For negative rules, filter to patterns that obfuscation should eliminate
    if args_negative:
        negative_categories = {"api_string", "string", "wide_string", "syscall", "rich_header"}
        all_patterns = [p for p in all_patterns if p[2] in negative_categories]

    return all_patterns


# ---------------------------------------------------------------------------
# YARA rule generation
# ---------------------------------------------------------------------------

def format_hex_string(pat_bytes, max_width=60):
    """Format bytes as a YARA hex string, wrapping long lines."""
    hex_str = " ".join(f"{b:02X}" for b in pat_bytes)
    return hex_str


def sanitise_rule_name(name):
    """Ensure the rule name is a valid YARA identifier."""
    name = re.sub(r"[^A-Za-z0-9_]", "_", name)
    if name and name[0].isdigit():
        name = "_" + name
    return name


def generate_yara_rule(name, patterns, description="", imphash=None,
                       negative=False, min_condition=3):
    """
    Generate a YARA rule from extracted patterns.

    Parameters:
        name:          Rule name (will be sanitised)
        patterns:      List of (bytes|None, description, category) tuples
        description:   Rule meta description
        imphash:       Import hash to include as a condition
        negative:      If True, generate a rule that matches when patterns are ABSENT
        min_condition: Minimum number of string matches for the condition
    """
    rule_name = sanitise_rule_name(name)
    if negative:
        rule_name += "_negative"

    lines = []
    lines.append(f"rule {rule_name} {{")
    lines.append(f"    meta:")
    lines.append(f'        description = "{description}"')
    lines.append(f'        generated_by = "yara-gen.py"')
    lines.append(f'        date = "{_today()}"')
    if negative:
        lines.append(f'        purpose = "Verify obfuscation removed detectable patterns"')
    if imphash:
        lines.append(f'        imphash = "{imphash}"')

    # Build string definitions
    byte_patterns = [(p, d, c) for p, d, c in patterns if p is not None]

    if byte_patterns:
        lines.append(f"    strings:")
        for i, (pat, desc, cat) in enumerate(byte_patterns):
            safe_desc = desc.replace('"', '\\"')
            hex_str = format_hex_string(pat)
            # Use $a for ASCII, $w for wide, $s for byte patterns
            prefix = "a" if cat in ("api_string", "string") else (
                "w" if cat == "wide_string" else "s"
            )
            lines.append(f"        ${prefix}{i} = {{ {hex_str} }}  // {safe_desc}")

    # Build condition
    lines.append(f"    condition:")

    conditions = []
    conditions.append("uint16(0) == 0x5A4D")

    if imphash:
        conditions.append(f'pe.imphash() == "{imphash}"')

    num_strings = len(byte_patterns)
    if num_strings > 0:
        match_count = min(min_condition, max(1, num_strings // 2))

        if negative:
            # Negative rule: flag if any of these patterns are still present
            conditions.append(f"any of them")
        else:
            if match_count >= num_strings:
                conditions.append("all of them")
            else:
                conditions.append(f"{match_count} of them")

    lines.append(f"        {' and '.join(conditions)}")
    lines.append("}")
    lines.append("")

    return "\n".join(lines)


def _today():
    """Return today's date as YYYY-MM-DD."""
    from datetime import date
    return date.today().isoformat()


def generate_rule_file(input_path, output_path, rule_name, negative=False,
                       min_condition=3):
    """Generate a complete YARA rule file for a single PE."""
    data = read_pe(input_path)
    filename = os.path.basename(input_path)

    # Extract patterns
    patterns = extract_pe_patterns(data, args_negative=negative)

    if not patterns:
        print(f"[!] No patterns extracted from {filename}")
        return False

    # Get imphash
    imphash = calculate_imphash(data)

    # File header
    header_lines = [
        f"// YARA rule generated by yara-gen.py",
        f"// Source: {filename}",
        f"// SHA256: {hashlib.sha256(data).hexdigest()}",
        f"// File size: {len(data)} bytes",
    ]
    if imphash:
        header_lines.append(f"// Imphash: {imphash}")

    rich_hash = extract_rich_header_pattern(data)
    if rich_hash:
        header_lines.append(f"// Rich header hash: {rich_hash}")

    header_lines.append("")

    # Check if we need the PE module
    needs_pe_module = imphash is not None
    if needs_pe_module:
        header_lines.insert(0, 'import "pe"')
        header_lines.insert(1, "")

    # Description
    if negative:
        desc = f"Negative detection rule for {filename} - patterns that should be absent after obfuscation"
    else:
        desc = f"Detection patterns extracted from {filename}"

    # Generate rule
    rule_text = generate_yara_rule(
        name=rule_name,
        patterns=patterns,
        description=desc,
        imphash=imphash if not negative else None,
        negative=negative,
        min_condition=min_condition,
    )

    full_output = "\n".join(header_lines) + rule_text

    with open(output_path, "w") as f:
        f.write(full_output)

    # Summary
    categories = {}
    for _, _, cat in patterns:
        categories[cat] = categories.get(cat, 0) + 1

    byte_count = sum(1 for p, _, _ in patterns if p is not None)
    print(f"[+] Generated: {output_path}")
    print(f"    Rule: {sanitise_rule_name(rule_name)}{'_negative' if negative else ''}")
    print(f"    Patterns: {len(patterns)} total, {byte_count} byte patterns")
    print(f"    Categories: {', '.join(f'{k}={v}' for k, v in sorted(categories.items()))}")
    if imphash:
        print(f"    Imphash: {imphash}")

    return True


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Generate YARA rules from PE payload artifacts"
    )

    # Input options (mutually exclusive)
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "--input", dest="input_file",
        help="Single PE file to analyse"
    )
    input_group.add_argument(
        "--input-dir",
        help="Directory of PE files (batch mode)"
    )

    # Output options
    parser.add_argument(
        "--output", dest="output_file",
        help="Output .yar file path (single file mode)"
    )
    parser.add_argument(
        "--output-dir",
        help="Output directory for .yar files (batch mode)"
    )

    # Rule configuration
    parser.add_argument(
        "--name", default="MAAS_Payload",
        help="YARA rule name (default: MAAS_Payload)"
    )
    parser.add_argument(
        "--negative", action="store_true",
        help="Generate negative rules (patterns that should NOT be present after obfuscation)"
    )
    parser.add_argument(
        "--min-condition", type=int, default=3,
        help="Minimum number of string matches in the condition clause (default: 3)"
    )
    parser.add_argument(
        "--extensions", default=".exe,.dll,.sys,.bin",
        help="File extensions to process in batch mode (comma-separated, default: .exe,.dll,.sys,.bin)"
    )

    args = parser.parse_args()

    # Single file mode
    if args.input_file:
        if not os.path.isfile(args.input_file):
            print(f"[!] Input file not found: {args.input_file}", file=sys.stderr)
            sys.exit(1)

        output = args.output_file
        if not output:
            base = os.path.splitext(args.input_file)[0]
            suffix = "-negative" if args.negative else ""
            output = f"{base}{suffix}.yar"

        success = generate_rule_file(
            args.input_file, output, args.name,
            negative=args.negative,
            min_condition=args.min_condition,
        )
        sys.exit(0 if success else 1)

    # Batch mode
    if args.input_dir:
        if not os.path.isdir(args.input_dir):
            print(f"[!] Input directory not found: {args.input_dir}", file=sys.stderr)
            sys.exit(1)

        output_dir = args.output_dir or args.input_dir
        os.makedirs(output_dir, exist_ok=True)

        extensions = tuple(args.extensions.split(","))
        pe_files = [
            f for f in os.listdir(args.input_dir)
            if os.path.isfile(os.path.join(args.input_dir, f))
            and any(f.lower().endswith(ext) for ext in extensions)
        ]

        if not pe_files:
            print(f"[!] No PE files found in {args.input_dir} with extensions {extensions}")
            sys.exit(1)

        print(f"[*] Processing {len(pe_files)} file(s) from {args.input_dir}")
        success_count = 0

        for pe_file in sorted(pe_files):
            input_path = os.path.join(args.input_dir, pe_file)
            base_name = os.path.splitext(pe_file)[0]

            # Generate rule name from filename
            rule_name = f"MAAS_{sanitise_rule_name(base_name)}"
            suffix = "-negative" if args.negative else ""
            output_path = os.path.join(output_dir, f"{base_name}{suffix}.yar")

            try:
                ok = generate_rule_file(
                    input_path, output_path, rule_name,
                    negative=args.negative,
                    min_condition=args.min_condition,
                )
                if ok:
                    success_count += 1
            except Exception as e:
                print(f"[!] Error processing {pe_file}: {e}", file=sys.stderr)

        print(f"\n[+] Generated {success_count}/{len(pe_files)} YARA rule files in {output_dir}")
        sys.exit(0 if success_count > 0 else 1)


if __name__ == "__main__":
    main()
