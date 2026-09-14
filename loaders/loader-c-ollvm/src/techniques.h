#ifndef TECHNIQUES_H
#define TECHNIQUES_H

#include "dispatch.h"

BOOL tech_nt_thread(unsigned char *sc, size_t len);
BOOL tech_nt_apc(unsigned char *sc, size_t len);
BOOL tech_nt_section(unsigned char *sc, size_t len);
BOOL tech_nt_callback(unsigned char *sc, size_t len);
BOOL tech_nt_suspended(unsigned char *sc, size_t len);

#endif /* TECHNIQUES_H */
