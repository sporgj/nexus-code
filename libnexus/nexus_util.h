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


#ifdef __cplusplus
}
#endif
