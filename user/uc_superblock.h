#pragma once
#include <stdbool.h>

#include "uc_types.h"

typedef struct {
    shadow_t root_dnode;
    crypto_context_t crypto_context;
} superblock_t;

superblock_t * superblock_new();

superblock_t * superblock_from_file(char * path);

void superblock_free(superblock_t * super);

bool superblock_flush(superblock_t * super, char * path);
