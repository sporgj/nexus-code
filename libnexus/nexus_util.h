#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "nexus_uuid.h"

#include <stdlib.h>

#define nexus_free(ptr)                                                        \
    do {                                                                       \
        free(ptr);                                                             \
        ptr = NULL;                                                            \
    } while (0)






int nexus_strtoi8 (char * str, int8_t   * value);
int nexus_strtou8 (char * str, uint8_t  * value);
int nexus_strtoi16(char * str, int16_t  * value);
int nexus_strtou16(char * str, uint16_t * value);
int nexus_strtoi32(char * str, int32_t  * value);
int nexus_strtou32(char * str, uint32_t * value);
int nexus_strtoi64(char * str, int64_t  * value);
int nexus_strtou64(char * str, uint64_t * value);


char *
nexus_strncat(char * dest, const char * src, size_t maxlen);


// joining paths

char *
nexus_filepath_from_name(char * directory, const char * filename);

char *
nexus_filepath_from_uuid(const char * dirpath, struct nexus_uuid * uuid);


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
