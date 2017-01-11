#pragma once
#include <stdbool.h>

#include "uc_types.h"

supernode_t * superblock_new();

supernode_t * superblock_from_file(char * path);

void superblock_free(supernode_t * super);

bool superblock_flush(supernode_t * super, char * path);
