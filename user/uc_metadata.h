#pragma once
#include "uc_dirnode.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Returns the dirnode from the metadata
 * @param is shadow name
 */
uc_dirnode_t * metadata_get_dirnode(const shadow_t *);

/**
 * Called whenever the dirnode is modified
 * @param the dirnode to dirty
 */
int metadata_dirty_dirnode(uc_dirnode_t *);

#ifdef __cplusplus
}
#endif
