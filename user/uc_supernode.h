#pragma once
#include <stdbool.h>

#include "uc_types.h"

#ifdef __cplusplus
extern "C" {
#endif

supernode_t * supernode_new();

supernode_t * supernode_from_file(const char * path);

void supernode_free(supernode_t * super);

bool supernode_write(supernode_t * super, const char * path);

uint8_t * supernode_hash(supernode_t * super);

#ifdef __cplusplus
}
#endif
