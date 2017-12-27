#pragma once

#include "nexus_uuid.h"

struct volume_usertable {
    struct nexus_uuid my_uuid;
    struct nexus_uuid supernode_uuid;;
};


/**
 * Creates a new usertable
 *
 * @param supernode_uuid
 * @return NULL on failure
 */
struct volume_usertable *
volume_usertable_create(struct nexus_uuid * supernode_uuid);

/**
 * Writes the usertable to the datastore
 * @param usertable
 * @return 0 on success
 */
int
volume_usertable_store(struct volume_usertable * usertable,
                       crypto_mac_t            * usertable_mac);

void
volume_usertable_free(struct volume_usertable * usertable);
