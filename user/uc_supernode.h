#pragma once
#include <stdbool.h>

#include "uc_types.h"

typedef struct {
    shadow_t root_dnode;
    crypto_context_t crypto_context;
} supernode_t;

supernode_t * superblock_new();

supernode_t * superblock_from_file(char * path);

void superblock_free(supernode_t * super);

bool superblock_flush(supernode_t * super, char * path);
