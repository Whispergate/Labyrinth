# Evasion and Obfuscation

This document covers the evasion techniques available in the MAAS pipeline: compiler-level obfuscation, packing, indirect syscalls, PE metadata sanitisation, code signing, and DLL sideloading.

---

## OLLVM Obfuscation

The pipeline uses Obfuscator-LLVM (OLLVM) as a Clang pass plugin loaded at compile time. When any `ollvm-*` obfuscation profile is selected and the `c-ollvm` language is chosen, the build invokes:

```
clang --target=x86_64-w64-mingw32 -fpass-plugin=/opt/ollvm/lib/libOLLVMPipeline.so \
    -c <sources> -Isrc -O1
```

Clang compiles the C sources with OLLVM passes applied. The resulting object files are then linked with MinGW GCC (`x86_64-w64-mingw32-gcc`) to produce the final PE. This split (Clang for compilation, GCC for linking) is necessary because OLLVM operates at the IR level through Clang, while the `wclang` wrappers handle the cross-compilation target.

### Profiles

The four OLLVM profiles control which transformation passes are applied:

| Profile | Passes | Use Case |
|---------|--------|----------|
| `ollvm-cff` | Control Flow Flattening | Lightweight obfuscation with minimal size increase. Good for initial testing or when binary size is constrained. |
| `ollvm-bcf-cff` | Bogus Control Flow + Control Flow Flattening | Moderate obfuscation. Inserts opaque predicates and dead code paths on top of CFF. Used by the `evasive-c-dll` profile for sideload DLLs where some size tolerance exists. |
| `ollvm-full` | CFF + BCF + Instruction Substitution + String Encryption | The standard evasion profile. Used by `evasive-c`, `evasive-c-signed`, and `packed-ollvm`. Provides strong static analysis resistance at the cost of roughly 2-4x binary size increase. |
| `ollvm-heavy` | All passes with high iteration counts | Maximum obfuscation. All passes from `ollvm-full` plus elevated iteration parameters for deeper transformation. Produces large binaries (5-10x). Use when detection avoidance is the sole priority and binary size does not matter. Used by the `evasive-c-heavy` profile. |

### When to Use Each

- **Quick iteration / debugging**: Skip OLLVM entirely (`none`); use the `quick-test` profile.
- **Standard ops**: `ollvm-full` balances evasion against reasonable binary size.
- **DLL sideloading**: `ollvm-bcf-cff` keeps the proxy DLL small enough to avoid suspicion while still defeating static signatures.
- **Hardened targets**: `ollvm-heavy` when you expect aggressive static analysis and can tolerate a large binary.

---

## Garble (Go)

Garble is the obfuscation tool for Go loaders. It strips and randomises symbols, encrypts string literals, and removes package path information from the compiled binary.

### What It Obfuscates

- **String literals**: The `-literals` flag encrypts all string constants in the binary, decrypting them at runtime.
- **Symbols**: Function names, type names, and variable names are replaced with random strings.
- **Package paths**: Import paths are stripped so the binary does not reveal its Go module structure.
- **Debug info**: The `-tiny` flag removes all DWARF debug information, and `-ldflags="-s -w"` strips the symbol table and debug data from the linker.

### Build Command

```bash
GOOS=windows GOARCH=amd64 \
garble -literals -tiny build \
    -o loader.exe -ldflags="-s -w" \
    ./cmd/loader
```

For ARM64, set `GOARCH=arm64`. The build runs inside the `maas-builder-go` Docker image.

---

## Calypso

Calypso is a PE packer written in C++23. It auto-detects input types (native PE, .NET assembly, or raw shellcode) and wraps them in a new executable with built-in evasion. The pipeline supports two modes controlled by the `CALYPSO_MODE` parameter:

- **Pack mode** (`pack`): Takes a compiled custom loader, converts it to shellcode via donut_ollvm, encrypts it, and wraps it in Calypso's own loader. This produces a loader-in-loader: the custom loader's execution techniques plus Calypso's evasion. The tradeoff is that stacking two loaders increases detection surface.
- **Standalone mode** (`standalone`): Takes raw shellcode directly (no custom loader, no shellcrypt encryption) and produces a single executable using Calypso's own C++23 loader. This gives a single-layer output with lower detection signatures. Calypso handles its own encryption, encoding, and compression internally.

### Capabilities

- **Encryption**: AES-256 (ECB/CBC) or XOR encryption of the payload, decrypted only in memory at runtime.
- **Encoding**: UUID, MAC address, and other encoding schemes for payload obfuscation.
- **Compression**: Zlib, LZ4, or RLE compression of the payload before encryption.
- **AMSI bypass**: 6 methods for bypassing the Antimalware Scan Interface (e.g. `--amsi hwbp`, `--amsi context-corrupt`).
- **ETW evasion**: 7 methods for evading Event Tracing for Windows (e.g. `--etw hwbp`, `--etw complus`).
- **Syscall evasion**: Hell's Gate, Halo's Gate, and indirect syscalls for bypassing userland EDR hooks.
- **Ntdll unhooking**: Unhooks ntdll.dll to bypass userland EDR hooks (`--unhook ntdll.dll`).
- **Sleep delay**: Configurable sleep delay before execution to evade sandbox time-based analysis (`--sleep N`).
- **Drip loading**: Loads the payload incrementally to avoid large memory allocation spikes (`--drip`).
- **Module stomping**: Overwrites a legitimate loaded module's memory with the payload (`--module-stomp`).
- **Source-level obfuscation**: String encryption, junk code insertion, opaque predicates, and control flow graph flattening (`--obfuscate`).
- **LLVM IR-level obfuscation**: Optional LLVM IR-level obfuscation passes applied during compilation.
- **Self-delete**: Removes the executable from disk after execution (`--self-delete`).
- **PE-to-shellcode**: Uses donut_ollvm for PE-to-shellcode conversion (pack mode only).

### Pipeline Flow

In **pack mode**, the pipeline builds and encrypts the custom loader first, then passes the compiled PE to Calypso:

1. Generate shellcode (Mythic agent)
2. Encrypt shellcode with shellcrypt (XOR)
3. Build the custom loader (embeds encrypted shellcode)
4. Calypso wraps the compiled loader PE

In **standalone mode**, the pipeline skips both shellcrypt and the custom loader build, passing raw shellcode directly to Calypso:

1. Generate shellcode (Mythic agent)
2. Calypso wraps raw shellcode (handles its own encryption/encoding/compression)

### CLI Usage

Pack mode (native PE):

```
calypso --file <loader.exe> --peinject --output <out> --hide [flags]
```

Pack mode (.NET assembly):

```
calypso --file <loader.exe> --output <out> --hide [flags]
```

Standalone mode (raw shellcode):

```
calypso --file <shellcode.bin> --output <out> --hide [flags]
```

Calypso auto-detects the input type in all cases.

### Named Presets (from build-profiles.yml)

| Preset | Flags | Description |
|--------|-------|-------------|
| `fast` | `--unhook ntdll.dll` | Quick pack with ntdll unhooking. |
| `stealth` | `--unhook ntdll.dll --sleep 10 --amsi hwbp --etw hwbp` | AMSI and ETW bypass with sleep delay. |
| `stealth-obfuscated` | `--unhook ntdll.dll --sleep 10 --amsi hwbp --etw hwbp --obfuscate` | Stealth with source-level obfuscation. |
| `evasive` | `--unhook ntdll.dll --sleep 10 --amsi hwbp,context-corrupt --etw hwbp,complus --obfuscate --self-delete` | Multi-method AMSI/ETW bypass, obfuscation, and self-delete. |
| `evasive-drip` | `--unhook ntdll.dll --sleep 60 --amsi context-corrupt --etw complus --module-stomp --drip --obfuscate --self-delete` | Evasive with drip loading and module stomping. |
| `minimal` | `--no-antidebug --amsi none --etw none --cipher xor` | Encryption only, no evasion. |
| `none` | (empty) | No flags, Calypso defaults. |

Presets can be selected via the `PACKER_PRESET` parameter. Flag resolution order: explicit `PACKER_FLAGS`, then `PACKER_PRESET` (resolved from `build-profiles.yml`), then Calypso's built-in defaults.

---

## Indirect Syscalls

### The Problem

EDR products hook NT API functions in `ntdll.dll` by overwriting the first bytes of each stub with a `jmp` to their monitoring code. Any call to `NtAllocateVirtualMemory`, `NtProtectVirtualMemory`, or similar functions passes through the EDR's detour first. Standard `GetProcAddress`-based resolution still lands on the hooked stub.

### The Solution

The indirect syscall implementation (`syscalls.c`, `syscalls.h`, `syscalls_asm.S`) bypasses these hooks entirely:

1. **HellsGate**: At runtime, the resolver walks the PEB's `InMemoryOrderModuleList` to find `ntdll.dll`'s base address (avoiding `GetModuleHandle`, which may itself be hooked). It parses the export address table and reads the raw bytes of each `Nt*` stub to extract the syscall service number (SSN) from the `mov eax, <SSN>` instruction.

2. **HalosGate**: If the target stub's bytes do not match the expected pattern (indicating it has been hooked), the resolver searches neighbouring stubs above and below the target. Since SSNs are sequential in the syscall table, the correct SSN can be extrapolated from a clean neighbour.

3. **Indirect execution**: Rather than issuing the `syscall` instruction from the loader's own memory (which EDRs flag as suspicious), the resolver locates a `syscall; ret` gadget within `ntdll.dll`'s `.text` section. The assembly stubs in `syscalls_asm.S` set up the register arguments and jump to this gadget, so the `syscall` instruction always executes from legitimate `ntdll` memory.

### Resolved Functions

The following NT APIs are resolved at startup via `syscalls_init()`:

- `NtAllocateVirtualMemory`
- `NtProtectVirtualMemory`
- `NtCreateThreadEx`
- `NtQueueApcThread`
- `NtTestAlert`
- `NtWaitForSingleObject`
- `NtCreateSection`
- `NtMapViewOfSection`

### Build Integration

Set `USE_INDIRECT_SYSCALLS` to `1` in the loader's `src/config.h`. The build scripts already discover both `*.c` and `*.S` files, so no compiler flags or build changes are needed. Set it to `0` to fall back to `GetProcAddress`-based resolution.

---

## PE Metadata Sanitisation

The `pe-sanitise.py` tool strips or replaces identifying metadata from compiled PE files. The pipeline invokes it during the "PE Sanitisation" stage:

```bash
python3 tools/pe-sanitise.py loader.* \
    --strip-rich --randomise-timestamp \
    --strip-debug --strip-version-info
```

### Operations

| Operation | Flag | What It Does | Why It Matters |
|-----------|------|-------------|----------------|
| Strip Rich header | `--strip-rich` | Zeros out the Rich header (DanS signature through the XOR key). | The Rich header encodes the exact compiler toolchain (tool IDs, build numbers, usage counts). Analysts use it to fingerprint the build environment and link samples to the same developer or toolchain. |
| Fake Rich header | `--fake-rich` | Replaces the Rich header with a plausible fake containing randomised Visual Studio 2019-2024 tool IDs (linker, compiler, assembler, resource compiler). | Instead of removing the Rich header (which is itself a signal), this plants a realistic-looking one that points to a standard MSVC toolchain. |
| Randomise timestamp | `--randomise-timestamp` | Replaces the PE timestamp with a random value, or with `--use-pool` selects from a curated pool of real Visual Studio release timestamps (VS 2019 through VS 2022 17.11). | The PE timestamp reveals when the binary was compiled. A recent or unusual timestamp aids attribution and timeline analysis. Pool mode produces timestamps that match legitimate MSVC builds. |
| Strip PDB path | `--strip-pdb` | Zeros out PDB path strings in CODEVIEW debug directory entries (both RSDS and NB10 formats). | PDB paths contain the developer's filesystem path (e.g., `C:\Users\operator\source\...`), leaking usernames, project names, and directory structure. |
| Strip debug directory | `--strip-debug` | Zeros the debug directory RVA and size in the optional header. | Removes all debug directory entries, including CODEVIEW references, reproducibility hashes, and other debug metadata. |
| Strip version info | `--strip-version-info` | Removes the VS_VERSION_INFO resource. | Version info contains company name, product name, file description, and internal name. Cross-compiled binaries often have missing or inconsistent version info that stands out. |
| Recalculate checksum | *(automatic)* | Recalculates the PE checksum after modifications using the standard PE checksum algorithm. | An invalid checksum can flag the binary as tampered. The tool recalculates it after all other operations. |

---

## Code Signing (Limelighter)

The pipeline uses Limelighter to apply Authenticode signatures to compiled payloads. Signing is configured via `signing-profiles.yml` and the `SIGNING_PROFILE` pipeline parameter.

### Modes

- **Real mode** (`mode: real`): Clones the TLS certificate from a live domain and uses it to sign the binary. The signature will not pass strict verification (it is not a real code-signing cert), but it adds a certificate chain that looks legitimate to casual inspection and some automated tools.
- **Self-signed mode** (`mode: self-signed`): Generates a self-signed certificate with a custom domain and signs the binary with it. Less convincing but useful for testing or internal operations.

### Available Profiles

| Profile | Domain | Mode | Description |
|---------|--------|------|-------------|
| `microsoft` | `www.microsoft.com` | real | Clone Microsoft's code signing certificate. |
| `google` | `www.google.com` | real | Clone Google's code signing certificate. |
| `intel` | `www.intel.com` | real | Clone Intel's code signing certificate. |
| `custom` | `internal-tools.contoso.com` | self-signed | Self-signed with custom domain. |
| `none` | -- | -- | Skip signing. |

---

## DLL Sideloading

### Concept

DLL sideloading exploits the Windows DLL search order. A legitimate application loads a DLL by name from its own directory before checking system paths. By placing a malicious proxy DLL alongside the legitimate executable, the proxy is loaded instead. The proxy forwards all exported functions to the original DLL (renamed with an `_orig` suffix) so the host application functions normally, while executing shellcode via `DllMain` on load.

### Supported Targets

The sideload generator (`pipeline/tools/sideload-gen/sideload_gen.py`) includes export databases for the following DLLs:

| Target DLL | Common Host Applications |
|------------|------------------------|
| `version.dll` | Many Windows applications (Explorer, Office, installers). Exports version-query APIs (`GetFileVersionInfoA/W`, `VerQueryValueA/W`, etc.). |
| `winmm.dll` | Media applications, some system utilities. Exports multimedia APIs (`PlaySoundA/W`, `timeGetTime`, `waveOutOpen`, etc.). |
| `dbghelp.dll` | Debuggers, crash reporters, development tools. Exports symbol and stack-walk APIs (`MiniDumpWriteDump`, `SymInitialize`, `StackWalk64`, etc.). |
| `amsi.dll` | PowerShell, .NET CLR, Office VBA. Exports AMSI scan APIs (`AmsiInitialize`, `AmsiScanBuffer`, etc.). Sideloading this DLL effectively disables AMSI for the host process. |
| `userenv.dll` | Various system services and management tools. Exports environment and profile APIs (`CreateEnvironmentBlock`, `LoadUserProfileA/W`, etc.). |
| `crypt32.dll` | Applications performing certificate operations. Exports certificate store and crypto APIs (`CertOpenStore`, `CertFindCertificateInStore`, etc.). |

### Using the Generator

The generator produces C source, a module-definition file (`.def`), and a `Makefile` for each proxy:

```bash
python3 pipeline/tools/sideload-gen/sideload_gen.py \
    --target version.dll \
    --shellcode-header shellcode/shellcode.h \
    --output-dir loaders/loader-sideload-version/
```

- `--target`: Which DLL to proxy (one of the supported targets above).
- `--shellcode-header`: Path to the encrypted shellcode header produced by the pipeline's "Encrypt Shellcode" stage. Omit for a placeholder `0xCC` breakpoint stub.
- `--output-dir`: Where to write the generated source files.

### Compilation

The generated proxy compiles with the `maas-builder-c` Docker image:

```bash
docker run --rm -v $PWD:/build maas-builder-c make -C /build
```

The `OUTPUT_FORMAT=dll` pipeline path can consume these templates directly. Copy the generated directory into `loaders/loader-sideload-<target>/` and the standard build pipeline will compile it.

### Deployment

1. Rename the original target DLL to `<name>_orig.dll` (e.g., `version_orig.dll`).
2. Place the compiled proxy DLL as `<name>.dll` in the same directory as the host executable.
3. When the application loads, it picks up the proxy, which forwards all API calls to `<name>_orig.dll` while executing the embedded shellcode.
