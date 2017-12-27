/**
 * Copyright (c) Judicael Djoko <jbriand@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software. You are permitted to use, redistribute, and modify it
 * as specified in the file "PETLAB_LICENSE".
 */
#pragma once

#include "nexus_uuid.h"

struct dirnode {
    struct nexus_uuid my_uuid;
    struct nexus_uuid root_uuid;
};


/**
 * Creates a new dirnode
 *
 * @param root_uuid
 * @return NULL on failure
 */
struct dirnode *
dirnode_create(struct nexus_uuid * root_uuid);

/**
 * Writes dirnode to datastore
 *
 * @param dirnode
 * @return 0 on success
 */
int
dirnode_store(struct dirnode * dirnode);

void
dirnode_free(struct dirnode * dirnode);
