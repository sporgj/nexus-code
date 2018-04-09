/*
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "xxhash.c"

#include "../enclave_internal.h"

int
nexus_uuid_gen(struct nexus_uuid * uuid)
{
    sgx_read_rand(uuid->raw, NEXUS_UUID_SIZE);

    return 0;
}

int
nexus_uuid_compare(struct nexus_uuid * src_uuid, struct nexus_uuid * dst_uuid)
{
    return memcmp(src_uuid, dst_uuid, sizeof(struct nexus_uuid));
}

struct nexus_uuid *
nexus_uuid_clone(struct nexus_uuid * uuid)
{
    struct nexus_uuid * new_uuid = NULL;

    new_uuid = calloc(sizeof(struct nexus_uuid), 1);

    if (new_uuid == NULL) {
	return NULL;
    }

    memcpy(new_uuid->raw, uuid->raw, NEXUS_UUID_SIZE);

    return new_uuid;
}

int
nexus_uuid_copy(struct nexus_uuid * src_uuid,
		struct nexus_uuid * dst_uuid)
{
    memcpy(dst_uuid->raw, src_uuid->raw, NEXUS_UUID_SIZE);

    return 0;
}

bool
nexus_uuid_is_valid(struct nexus_uuid * uuid)
{
    int i = 0;

    for (i = 0; i < NEXUS_UUID_SIZE; i++) {
        if (uuid->raw[i] != 0) {
            return true;
        }
    }

    return false;
}

uint32_t
nexus_uuid_hash(struct nexus_uuid * uuid)
{
    return (uint32_t)(XXH32(uuid, sizeof(struct nexus_uuid), 0));
}
