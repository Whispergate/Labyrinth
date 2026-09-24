# Shellcode Loaders

## Structure

### Architecture Pattern

Every loader in the project follows the same dispatch-table design, regardless of language. The pattern has three moving parts:

1. **Dispatch table**: An array of `(name, function_pointer)` pairs. Each entry maps a technique name to an injection function.
2. **Technique selection**: The loader parses `-t <N>` from the command line to index into the table. If no flag is given, technique 0 is used.
3. **Payload lifecycle**: Shellcode is embedded at build time as a XOR-encrypted blob (via a generated `shellcode.*` source file). At runtime the loader decrypts it, passes the raw buffer to the selected technique function, then wipes the buffer with a secure zero before exiting.

The function pointer signature is the same across all loaders:

| Language | Signature |
|----------|-----------|
| C (MinGW/OLLVM) | `BOOL (*inject_fn)(unsigned char *sc, size_t len)` |
| Go | `func(sc []byte) bool` |
| Rust | `fn(&[u8]) -> bool` |
| C# | `Func<byte[], bool>` |

### File Layout

All loaders share a common structure:

```
loaders/loader-<name>/
  build.sh                                      # build script (receives output_format, target_arch, obfuscation)
  loader.yml                                    # build metadata (docker_image, agent_label, shellcode_dest, shellcode_format, volumes)
  src/
    config.h / config.rs / Config.cs / config.go  # technique selection, syscall mode, XOR key length
    main.c / main.go / main.rs / Program.cs       # entry point + dispatch table
    dispatch.h                                    # inject_fn typedef (C only)
    techniques.h / mod.rs / technique.go          # technique declarations
    techniques/                                   # one file per injection technique
      nt_thread.c / nt_thread.go / ...
    payload.c / payload.go / Payload.cs           # decrypt + wipe helpers
    shellcode.h / shellcode.go / shellcode.rs     # generated at build time (XOR blob + key)
    ntapi.h / ntapi.c / NtApi.cs / ntapi.go       # NT API typedefs or P/Invoke declarations
    syscalls.h                                    # indirect syscall support (C only)
    syscalls.c                                    # HellsGate/HalosGate resolver (C only)
    syscalls_asm.S                                # assembly stubs (C only)
```

The C-MinGW loader uses Win32 API calls directly in most techniques, with NT API resolution only for `NtTestAlert` in the APC-self technique. The C-OLLVM loader resolves all NT APIs at runtime through `ntapi_resolve()`, which supports an optional indirect-syscall backend.

---

## Loader Reference

### C-MinGW

| Property | Value |
|----------|-------|
| Language | C (Win32 API) |
| Toolchain | `x86_64-w64-mingw32-gcc` (amd64), `aarch64-w64-mingw32-gcc` (arm64) |
| Docker image | `maas-builder-c` |
| Runner label | `linux-c` |
| Output formats | EXE, DLL |

**Injection techniques:**

| Index | Name | Description |
|-------|------|-------------|
| 0 | `createthread` | `VirtualAlloc` (RW), `memcpy`, `VirtualProtect` (RX), `CreateThread`, `WaitForSingleObject` |
| 1 | `enum_windows` | `VirtualAlloc` (RW), `memcpy`, `VirtualProtect` (RX), `EnumWindows` callback executes shellcode |
| 2 | `timer_queue` | `VirtualAlloc` (RW), `memcpy`, `VirtualProtect` (RX), `CreateTimerQueueTimer` fires shellcode as callback |
| 3 | `apc_self` | `VirtualAlloc` (RW), `memcpy`, `VirtualProtect` (RX), `QueueUserAPC` to current thread, `NtTestAlert` to flush |
| 4 | `fiber` | `ConvertThreadToFiber`, `VirtualAlloc` (RW), `memcpy`, `VirtualProtect` (RX), `CreateFiber`, `SwitchToFiber` |
| 5 | `section_map` | `NtCreateSection` (RWX), `NtMapViewOfSection` (RW), `memcpy`, `NtMapViewOfSection` (RX), `NtCreateThreadEx`, `NtWaitForSingleObject`. Avoids `VirtualAlloc`/`VirtualProtect` entirely. Always uses indirect syscalls via `ntapi_resolve()`. |

**Build command:**

```bash
x86_64-w64-mingw32-gcc -o loader.exe \
    $(find src -name '*.c' | sort | tr '\n' ' ') \
    -Isrc -lntdll -lkernel32 -mwindows -s -O2
```

**Dependencies:** MinGW-w64 cross-compiler. Links against `ntdll.dll` and `kernel32.dll`.

---

### C-OLLVM

| Property | Value |
|----------|-------|
| Language | C (NT API via runtime resolution) |
| Toolchain | Clang with OLLVM pass plugin (compile), MinGW-w64 GCC (link) |
| Docker image | `maas-builder-c` |
| Runner label | `linux-c` |
| Output formats | EXE, DLL |

**Injection techniques:**

| Index | Name | Description |
|-------|------|-------------|
| 0 | `nt_thread` | `NtAllocateVirtualMemory` (RW), `memcpy`, `NtProtectVirtualMemory` (RX), `NtCreateThreadEx`, `NtWaitForSingleObject` |
| 1 | `nt_apc` | `NtAllocateVirtualMemory` (RW), `memcpy`, `NtProtectVirtualMemory` (RX), `NtQueueApcThread` to current thread, `NtTestAlert` |
| 2 | `nt_section` | `NtCreateSection` (RWX), `NtMapViewOfSection` (RW), `memcpy`, `NtMapViewOfSection` (RX), `NtCreateThreadEx`, `NtWaitForSingleObject` |
| 3 | `nt_callback` | `NtAllocateVirtualMemory` (RW), `memcpy`, `NtProtectVirtualMemory` (RX), `EnumWindows` callback |
| 4 | `nt_suspended` | `NtAllocateVirtualMemory` (RW), `memcpy`, `NtProtectVirtualMemory` (RX), `NtCreateThreadEx` (suspended), `ResumeThread`, `NtWaitForSingleObject` |

All NT API functions are resolved at runtime through `ntapi_resolve()`. By default this uses `GetProcAddress` on `ntdll.dll`. With `USE_INDIRECT_SYSCALLS` set to `1` in `config.h`, it routes through assembly wrappers that execute the `syscall` instruction from within ntdll's own `.text` section.

**Build command:**

```bash
# Compile with OLLVM obfuscation
clang --target=x86_64-w64-mingw32 \
    -fpass-plugin=/opt/ollvm/lib/libOLLVMPipeline.so \
    -c $(find src -name '*.c' -o -name '*.S' | sort | tr '\n' ' ') -Isrc -O1

# Link with MinGW GCC
x86_64-w64-mingw32-gcc -o loader.exe obj/*.o -lntdll -lkernel32 -s
```

**Dependencies:** OLLVM-patched Clang with `libOLLVMPipeline.so`, MinGW-w64 for linking. Falls back to standard Clang if the pass plugin is not present.

**Special features:** Runtime NT API resolution. Optional indirect syscalls toggled via `config.h` (see the [Indirect Syscalls](#indirect-syscalls) section).

---

### Go-Garble

| Property | Value |
|----------|-------|
| Language | Go |
| Toolchain | `garble` (wraps `go build`) |
| Docker image | `maas-builder-go` |
| Runner label | `linux-go` |
| Go version | 1.24 |
| Output formats | EXE |

**Injection techniques:**

| Index | Name | Description |
|-------|------|-------------|
| 0 | `nt_thread` | `NtAllocateVirtualMemory` (RW), copy, `NtProtectVirtualMemory` (RX), `NtCreateThreadEx`, `NtWaitForSingleObject` |
| 1 | `nt_apc` | `NtAllocateVirtualMemory` (RW), copy, `NtProtectVirtualMemory` (RX), `NtQueueApcThread`, `NtTestAlert` |
| 2 | `nt_section` | `NtCreateSection`, `NtMapViewOfSection` (RW), copy, `NtMapViewOfSection` (RX), `NtCreateThreadEx`, `NtWaitForSingleObject` |
| 3 | `nt_callback` | `NtAllocateVirtualMemory` (RW), copy, `NtProtectVirtualMemory` (RX), `EnumWindows` callback |
| 4 | `nt_suspended` | `NtAllocateVirtualMemory` (RW), copy, `NtProtectVirtualMemory` (RX), `NtCreateThreadEx` (suspended), `ResumeThread`, `NtWaitForSingleObject` |

NT API calls go through `syscall.LazyDLL` / `LazyProc` for `ntdll.dll`, `kernel32.dll`, and `user32.dll`.

**Build command:**

```bash
GOOS=windows GOARCH=amd64 \
garble -literals -tiny build \
    -o loader.exe -ldflags="-s -w" \
    ./cmd/loader
```

**Dependencies:** Go 1.24+, [garble](https://github.com/burrowers/garble). No CGo or external C dependencies.

**Special features:** Garble obfuscates Go symbol names and string literals (`-literals`). The `-tiny` flag strips additional metadata.

---

### Rust

| Property | Value |
|----------|-------|
| Language | Rust |
| Toolchain | `cargo` cross-compiling to `x86_64-pc-windows-gnu` or `aarch64-pc-windows-gnullvm` |
| Docker image | `maas-builder-rust` |
| Runner label | `linux-rust` |
| Rust edition | 2021 |
| Output formats | EXE |

**Injection techniques:**

| Index | Name | Description |
|-------|------|-------------|
| 0 | `nt_thread` | Same NT API sequence as OLLVM/Go `nt_thread` |
| 1 | `nt_apc` | Same NT API sequence as OLLVM/Go `nt_apc` |
| 2 | `nt_section` | Same NT API sequence as OLLVM/Go `nt_section` |
| 3 | `nt_callback` | Same NT API sequence as OLLVM/Go `nt_callback` |
| 4 | `nt_suspended` | Same NT API sequence as OLLVM/Go `nt_suspended` |

**Build command:**

```bash
cargo build --release --target x86_64-pc-windows-gnu
```

**Dependencies:** Rust toolchain with the `x86_64-pc-windows-gnu` or `aarch64-pc-windows-gnullvm` target installed. No external crates.

**Special features:** Release profile uses `opt-level = "s"` (size optimization), LTO, symbol stripping, and `panic = "abort"`. The binary is set to `#![windows_subsystem = "windows"]` so no console window appears.

---

### C# (.NET)

| Property | Value |
|----------|-------|
| Language | C# |
| Toolchain | .NET 8 SDK (`dotnet publish`) |
| Runner label | `windows-dotnet` (native Windows agent, no Docker) |
| Framework | `net8.0-windows` |
| Output formats | EXE |

**Injection techniques:**

| Index | Name | Description |
|-------|------|-------------|
| 0 | `nt_thread` | Same NT API sequence as OLLVM/Go `nt_thread` |
| 1 | `nt_apc` | Same NT API sequence as OLLVM/Go `nt_apc` |
| 2 | `nt_section` | Same NT API sequence as OLLVM/Go `nt_section` |
| 3 | `nt_callback` | Same NT API sequence as OLLVM/Go `nt_callback` (uses `EnumWindows` via `user32.dll`) |
| 4 | `nt_suspended` | Same NT API sequence as OLLVM/Go `nt_suspended` |

NT API calls use P/Invoke `[DllImport("ntdll.dll")]` declarations in `NtApi.cs`. `EnumWindows` and `ResumeThread` are imported from `user32.dll` and `kernel32.dll` respectively.

**Build command:**

```powershell
dotnet publish src\Loader.csproj `
    -c Release -r win-x64 `
    --self-contained true `
    -p:PublishSingleFile=true `
    -p:PublishTrimmed=true `
    -o .
```

**Dependencies:** .NET 8 SDK. Published as a self-contained, single-file, trimmed binary. Requires `AllowUnsafeBlocks`.

---

## Injection Techniques

### Cross-Loader Technique Matrix

| Technique | API Sequence | C-MinGW | C-OLLVM | Go | Rust | C# | ATT&CK |
|-----------|-------------|---------|---------|-----|------|-----|--------|
| `createthread` | VirtualAlloc, VirtualProtect, CreateThread | Yes | -- | -- | -- | -- | T1055.002 |
| `enum_windows` | VirtualAlloc, VirtualProtect, EnumWindows | Yes | -- | -- | -- | -- | T1055.004 |
| `timer_queue` | VirtualAlloc, VirtualProtect, CreateTimerQueueTimer | Yes | -- | -- | -- | -- | T1055.004 |
| `apc_self` | VirtualAlloc, VirtualProtect, QueueUserAPC, NtTestAlert | Yes | -- | -- | -- | -- | T1055.004 |
| `fiber` | VirtualAlloc, VirtualProtect, CreateFiber, SwitchToFiber | Yes | -- | -- | -- | -- | T1055.004 |
| `section_map` | NtCreateSection, NtMapViewOfSection (RW+RX), NtCreateThreadEx | Yes | -- | -- | -- | -- | T1055.012 |
| `nt_thread` | NtAllocateVirtualMemory, NtProtectVirtualMemory, NtCreateThreadEx | -- | Yes | Yes | Yes | Yes | T1055.002 |
| `nt_apc` | NtAllocateVirtualMemory, NtProtectVirtualMemory, NtQueueApcThread, NtTestAlert | -- | Yes | Yes | Yes | Yes | T1055.004 |
| `nt_section` | NtCreateSection, NtMapViewOfSection (RW+RX), NtCreateThreadEx | -- | Yes | Yes | Yes | Yes | T1055.012 |
| `nt_callback` | NtAllocateVirtualMemory, NtProtectVirtualMemory, EnumWindows | -- | Yes | Yes | Yes | Yes | T1055.004 |
| `nt_suspended` | NtAllocateVirtualMemory, NtProtectVirtualMemory, NtCreateThreadEx (CREATE_SUSPENDED), ResumeThread | -- | Yes | Yes | Yes | Yes | T1055.002 |

### Notes on Technique Differences

The C-MinGW loader uses high-level Win32 API calls (`VirtualAlloc`, `CreateThread`, etc.). These are straightforward and easy to debug but are more visible to user-mode hooks.

The other four loaders (C-OLLVM, Go, Rust, C#) all use native NT API calls directly. The C-OLLVM loader also supports bypassing user-mode hooks via indirect syscalls.

The `nt_section` technique avoids the usual allocate-write-protect pattern. Instead it creates a shared section object, maps a writable view for copying, then maps a second executable view at a different address. This separates the write and execute addresses, which is less commonly instrumented.

---

## Indirect Syscalls

Indirect syscall support applies to the two C loaders (MinGW and OLLVM). The Go, Rust, and C# loaders do not support it.

### How It Works

When `USE_INDIRECT_SYSCALLS` is set to `1` in `config.h`, the `ntapi_resolve()` function changes behavior. Instead of returning a `GetProcAddress` result, it returns a pointer to an assembly stub that:

1. Moves `rcx` into `r10` (Windows syscall calling convention)
2. Loads the resolved syscall service number (SSN) into `eax`
3. Jumps to a `syscall; ret` gadget located inside ntdll's `.text` section

Because the `syscall` instruction executes from legitimate ntdll memory, EDR products that check the return address of syscall instructions will see a valid ntdll address.

### SSN Resolution: HellsGate + HalosGate

The SSN resolver (`syscalls.c`) works as follows:

1. **Find ntdll base**: Walks the PEB `InMemoryOrderModuleList` to locate `ntdll.dll` without calling `GetModuleHandle`.
2. **Find export**: Walks ntdll's Export Address Table to locate the target function.
3. **HellsGate** (unhooked stub): Reads the stub's opcodes looking for the expected pattern (`4C 8B D1 B8 xx xx 00 00` = `mov r10, rcx; mov eax, <SSN>`). If the pattern matches, the SSN is extracted directly.
4. **HalosGate** (hooked stub): If the target stub's opcodes don't match (indicating an EDR hook), the resolver searches neighbouring stubs up to 512 positions in each direction (each stub is 32 bytes apart on x64). Once an unhooked neighbour is found, the SSN is calculated by offset.
5. **Syscall gadget**: The `.text` section is scanned for a `0F 05 C3` byte sequence (`syscall; ret`). The address of this gadget is stored alongside each SSN.

All SSN entries are resolved once by `syscalls_init()` at startup.

### Assembly Stubs

The stubs are in `syscalls_asm.S` using GAS Intel syntax. A macro generates one wrapper per NT function:

```asm
.macro INDIRECT_SYSCALL name
.globl Indirect\name
Indirect\name:
    mov   r10, rcx
    mov   eax, dword ptr [rip + sc_\name]        # SSN (offset 0)
    mov   r11, qword ptr [rip + sc_\name + 8]    # syscall gadget addr (offset 8)
    jmp   r11
.endm
```

Stubs are generated for: `NtAllocateVirtualMemory`, `NtProtectVirtualMemory`, `NtCreateThreadEx`, `NtQueueApcThread`, `NtTestAlert`, `NtWaitForSingleObject`, `NtCreateSection`, `NtMapViewOfSection`.

### Enabling Indirect Syscalls

Set `USE_INDIRECT_SYSCALLS` to `1` in the loader's `src/config.h`:

```c
#define USE_INDIRECT_SYSCALLS 1   // 1 = indirect syscalls, 0 = GetProcAddress
```

The build scripts already include `.S` assembly files alongside `.c` sources. No compiler flags or Jenkinsfile changes are needed. The technique functions call `ntapi_resolve()` as before; when indirect syscalls are enabled, the resolver returns the assembly wrapper instead of a `GetProcAddress` result.

---

## Adding a New Loader

1. Create the directory structure:
   ```
   loaders/loader-<name>/
     build.sh           # build script
     loader.yml         # build metadata
     src/
       config.*         # technique selection + settings
       main.<ext>       # dispatch table + CLI parsing
       techniques/      # one file per technique
       payload.<ext>    # decrypt/wipe
   ```

2. Implement the dispatch pattern:
   - Define a technique struct/type matching `(name, function_pointer)`.
   - Build a static registry array of all techniques.
   - Read the default technique index from the config file.
   - Parse `-t <N>` from argv, bounds-check the index.
   - Call `ldr_extract_shellcode` (or equivalent), invoke the selected technique, wipe the buffer.

3. Add a shellcode placeholder. The pipeline generates a `shellcode.*` file (C header, Go source, Rust source, or C# class) at build time via `shellcrypt`. Your loader needs to include/reference the generated file.

4. Create the build configuration (Makefile, Cargo.toml, .csproj, go.mod, etc.).

5. Create `loader.yml` with the build metadata:
   ```yaml
   docker_image: maas-builder-<lang>
   agent_label: linux-<lang>
   shellcode_dest: src/shellcode.<ext>
   shellcode_format: <c|go|rust|csharp>
   volumes:
     - /payloads:/payloads
   ```

6. Create `build.sh` that accepts three arguments (`<output_format> <target_arch> <obfuscation>`) and compiles the loader. The script should handle all compilation, linking, and output naming. See existing loaders for examples.

7. Add a build profile entry to `pipeline/build-profiles.yml`.

8. Add the build Docker image label to `range-config.yml` if a new builder image is needed.

No changes to the Jenkinsfile are needed. The generic build stage reads `loader.yml` and delegates to `build.sh` automatically.

---

## Adding a New Technique

All loaders follow the same process. The steps below use the C loaders as the example; adjust types and syntax for other languages.

1. **Write the technique function.** Create a new file in `src/techniques/` matching the `inject_fn` signature:

   ```c
   // src/techniques/my_technique.c
   #include "../dispatch.h"
   #include "../ntapi.h"    // if using NT API resolution (OLLVM)

   BOOL tech_my_technique(unsigned char *sc, size_t len) {
       // allocate, write, protect, execute
       return TRUE;
   }
   ```

   For the MinGW loader, use Win32 API calls directly. For the OLLVM loader, resolve NT APIs through `ntapi_resolve()`.

2. **Declare the function** in `src/techniques.h`:

   ```c
   BOOL tech_my_technique(unsigned char *sc, size_t len);
   ```

3. **Add to the dispatch table** in `src/main.c`:

   ```c
   static technique_t techniques[] = {
       // ... existing techniques ...
       { "my_technique", tech_my_technique },
   };
   ```

   The new technique is automatically assigned the next index. No other changes are needed; `NUM_TECHNIQUES` is computed from the array size.

4. **If the technique uses a new NT API** that isn't already defined:
   - Add the function typedef to `ntapi.h`
   - If indirect syscalls are supported, add the corresponding entries to `syscalls.h`, `syscalls.c`, `syscalls_asm.S`, and the wrapper map in `ntapi.c`

For non-C loaders, the equivalent steps are:
- **Go**: Add a `.go` file in `internal/techniques/`, implement the function matching `InjectFn`, and append to `Registry` in `technique.go`.
- **Rust**: Add a `.rs` file in `src/techniques/`, implement a `pub fn run(sc: &[u8]) -> bool`, add `mod my_technique;` and a `Technique` entry in `mod.rs`.
- **C#**: Add a `.cs` file in `src/Techniques/`, implement a `public static bool Run(byte[] sc)`, and add the tuple to the `Techniques` array in `Program.cs`.
