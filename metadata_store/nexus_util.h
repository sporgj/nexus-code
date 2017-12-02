#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <stdint.h>

#include "nexus.h"

#include "queue.h"

#define nexus_free(ptr)                                                        \
    do {                                                                       \
        free(ptr);                                                             \
        ptr = NULL;                                                            \
    } while (0)

/**
 * Reads a raw file from disk
 * @param fpath
 * @param p_buffer
 * @param p_size
 * @return 0 on success
 */
int
read_file(const char * fpath, uint8_t ** p_buffer, size_t * p_size);

int
write_file(const char * fpath, void * buffer, size_t size);


char *
my_strnjoin(char * dest, const char * join, const char * src, size_t max);

char *
my_strncat(char * dest, const char * src, size_t max);


char *
uuid_to_string(struct uuid * uuid);


char *
filepath_from_name(char * directory, const char * filename);

char *
filepath_from_uuid(const char * dir_path, struct uuid * uuid);

#ifdef __cplusplus
}
#endif
