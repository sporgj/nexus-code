#pragma once


#include "attribute_store.h"
#include "user_profile.h"


/// exports

struct abac_superinfo {
    struct nexus_uuid policy_store_uuid;
    struct nexus_uuid attribute_store_uuid;
} __attribute__((packed));


/**
 * Called at volume mount. Reads the attribute_store and user_profile from
 * the backend.
 */
int
abac_runtime_mount();

void
abac_runtime_destroy();

/**
 * Initializes the abac runtime files.
 */
int
abac_runtime_create();
