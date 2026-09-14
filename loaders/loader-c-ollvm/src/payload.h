#ifndef PAYLOAD_H
#define PAYLOAD_H

#include <stddef.h>

unsigned char *ldr_extract_shellcode(size_t *out_len);
void           ldr_wipe(unsigned char *buf, size_t len);

#endif /* PAYLOAD_H */
