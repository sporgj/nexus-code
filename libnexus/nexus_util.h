#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "nexus_internal.h"

#include <stdlib.h>

#define nexus_free(ptr)                                                        \
    do {                                                                       \
        free(ptr);                                                             \
        ptr = NULL;                                                            \
    } while (0)




#if 0
extern char *
my_strnjoin(char * dest, const char * join, const char * src, size_t max);

extern char *
my_strncat(char * dest, const char * src, size_t max);



extern char *
filepath_from_name(char * directory, const char * filename);

extern char *
filepath_from_uuid(const char * dir_path, struct uuid * uuid);

#endif

#ifdef __cplusplus
}
#endif
