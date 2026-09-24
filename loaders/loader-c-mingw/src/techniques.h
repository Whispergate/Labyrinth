#ifndef TECHNIQUES_H
#define TECHNIQUES_H

#include "dispatch.h"

BOOL tech_createthread(unsigned char *sc, size_t len);
BOOL tech_enum_windows(unsigned char *sc, size_t len);
BOOL tech_timer_queue(unsigned char *sc, size_t len);
BOOL tech_apc_self(unsigned char *sc, size_t len);
BOOL tech_fiber(unsigned char *sc, size_t len);
BOOL tech_section_map(unsigned char *sc, size_t len);

#endif /* TECHNIQUES_H */
