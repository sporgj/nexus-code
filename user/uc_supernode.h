#pragma once
#include <stdbool.h>

#include "uc_types.h"

#ifdef __cplusplus
extern "C" {
#endif

supernode_t * supernode_new();

supernode_t * supernode_from_file(const char * path);

void supernode_free(supernode_t * super);

bool supernode_flush(supernode_t * super, const char * path);

#ifdef __cplusplus
}
#endif
