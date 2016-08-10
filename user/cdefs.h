#pragma once

#include <sys/stat.h>
#include <sys/types.h>
#include <linux/limits.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define uerror(...)                   \
    {                                 \
        fprintf(stderr, " ! ");       \
        fprintf(stderr, __VA_ARGS__); \
        fprintf(stderr, "\n");        \
    }
#define ufatal(...)                                       \
    {                                                     \
        fprintf(stderr, " ! %s:%d ", __FILE__, __LINE__); \
        fprintf(stderr, __VA_ARGS__);                     \
        fprintf(stderr, "\n");                            \
    }
#define udebug(...)                                       \
    {                                                     \
        fprintf(stderr, " ! %s %s:%d ", __FUNCTION__,  __FILE__, __LINE__); \
        fprintf(stderr, __VA_ARGS__);                     \
        fprintf(stderr, "\n");                            \
    }
#define uinfo(...)                    \
    {                                 \
        fprintf(stdout, " . ");       \
        fprintf(stdout, __VA_ARGS__); \
        fprintf(stdout, "\n");        \
    }

#define EMPTY_STR_HEAP malloc(1)
#define UUID_STR_SIZE   37

extern char afs_path[];

char * get_afsx_file_path(char * fpath);
char * get_fname_from_path(char * fpath);

void init_afsx_paths(char * path);
