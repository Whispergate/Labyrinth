#ifndef DISPATCH_H
#define DISPATCH_H

#include <windows.h>
#include <stddef.h>

typedef BOOL (*inject_fn)(unsigned char *sc, size_t len);

typedef struct {
    const char *name;
    inject_fn   fn;
} technique_t;

#endif /* DISPATCH_H */
