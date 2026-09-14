#include "ntapi.h"

static HMODULE hNtdll = NULL;

FARPROC ntapi_resolve(const char *name) {
    if (!hNtdll) hNtdll = GetModuleHandleA("ntdll.dll");
    return GetProcAddress(hNtdll, name);
}
