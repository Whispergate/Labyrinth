/*
 * ntapi.c - NT API resolver
 *
 * To enable indirect syscalls:
 *   Set USE_INDIRECT_SYSCALLS to 1 in config.h
 *   Also compile syscalls.c and syscalls_asm.S
 *
 * For the Jenkinsfile, update the 'find' to include .S files:
 *   find src -name '*.c' -o -name '*.S' | sort | tr '\n' ' '
 *
 * For OLLVM: works with clang --target=x86_64-w64-mingw32
 * For MinGW: works with x86_64-w64-mingw32-gcc
 */

#include "ntapi.h"

#if USE_INDIRECT_SYSCALLS

#include "syscalls.h"
#include <string.h>

/*
 * When indirect syscalls are enabled, ntapi_resolve() returns pointers
 * to the assembly wrappers instead of GetProcAddress results.
 *
 * Callers must invoke syscalls_init() once before calling ntapi_resolve().
 */

/* Simple inline strcmp to avoid pulling in CRT (matches syscalls.c) */
static int ntapi_strcmp(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}

FARPROC ntapi_resolve(const char *name) {
    /* Map function names to their indirect-syscall wrappers */
    static const struct {
        const char *name;
        FARPROC     wrapper;
    } map[] = {
        { "NtAllocateVirtualMemory",  (FARPROC)IndirectNtAllocateVirtualMemory  },
        { "NtProtectVirtualMemory",   (FARPROC)IndirectNtProtectVirtualMemory   },
        { "NtCreateThreadEx",         (FARPROC)IndirectNtCreateThreadEx         },
        { "NtQueueApcThread",         (FARPROC)IndirectNtQueueApcThread         },
        { "NtTestAlert",              (FARPROC)IndirectNtTestAlert              },
        { "NtWaitForSingleObject",    (FARPROC)IndirectNtWaitForSingleObject    },
        { "NtCreateSection",          (FARPROC)IndirectNtCreateSection          },
        { "NtMapViewOfSection",       (FARPROC)IndirectNtMapViewOfSection       },
        { NULL, NULL }
    };

    for (int i = 0; map[i].name != NULL; i++) {
        if (ntapi_strcmp(map[i].name, name) == 0)
            return map[i].wrapper;
    }

    /* Fall through to GetProcAddress for any unlisted function */
    static HMODULE hNtdll = NULL;
    if (!hNtdll) hNtdll = GetModuleHandleA("ntdll.dll");
    return GetProcAddress(hNtdll, name);
}

#else /* !USE_INDIRECT_SYSCALLS */

static HMODULE hNtdll = NULL;

FARPROC ntapi_resolve(const char *name) {
    if (!hNtdll) hNtdll = GetModuleHandleA("ntdll.dll");
    return GetProcAddress(hNtdll, name);
}

#endif /* USE_INDIRECT_SYSCALLS */
