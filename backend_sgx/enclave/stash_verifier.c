
/* Responsible for verifying the returned file versions */

#include <nexus_hashtable.h>

#include "enclave_internal.h"



struct stashv_item {
    struct nexus_uuid  uuid;

    struct nexus_mac   mac;

    uint32_t           version;
};



static struct nexus_lru     * __stashv_cache = NULL;



void
__free_stash_item(uintptr_t element, uintptr_t key)
{
    nexus_free(element);
}


static int
__fetch_stash_item(struct nexus_uuid * uuid, struct nexus_mac * mac, uint32_t * version)
{
    struct stashv_item * stashed_item = nexus_lru_get(__stashv_cache, uuid);

    if (stashed_item) {
        *version = stashed_item->version;
        return 0;
    }


    // get it from the ocall
    {
        int err = -1;
        int ret = -1;

        err = ocall_versionstash_fetch(&ret, uuid, mac, version, global_volume);

        if (err) {
            log_error("ocall_versionstash_get FAILED\n");

            return -1;
        }

        return ret;
    }

    return -1;
}


int
__flush_stash_item(struct nexus_uuid * uuid, struct nexus_mac * mac, uint32_t version)
{
    int ret = -1;
    int err = ocall_versionstash_store(&ret, uuid, mac, version, global_volume);

    if (err) {
        log_error("ocall_versionstash_update FAILED\n");

        return -1;
    }

    return ret;
}


static inline int
__delete_stash_item(struct nexus_uuid * uuid)
{
    int ret = -1;
    int err = ocall_versionstash_delete(&ret, uuid, global_volume);

    if (err) {
        log_error("ocall_versionstash_del FAILED\n");

        return -1;
    }

    return ret;
}


int
stashv_init()
{
    __stashv_cache = nexus_lru_create(128, __uuid_hasher, __uuid_equals, __free_stash_item);

    return 0;
}


void
stashv_destroy()
{
    if (__stashv_cache) {
        nexus_lru_destroy(__stashv_cache);
    }
}


// removes entry from enclave only
int
stashv_drop(struct nexus_uuid * uuid)
{
    nexus_lru_del(__stashv_cache, uuid);
}

/**
 * removes the uuid from both enclave and untrusted memory
 */
int
stashv_delete(struct nexus_uuid * uuid)
{
    nexus_lru_del(__stashv_cache, uuid);
    return __delete_stash_item(uuid);
}


int
stashv_update(struct nexus_metadata * metadata)
{
    struct stashv_item * stashed_item = nexus_lru_get(__stashv_cache, &metadata->uuid);

    struct nexus_mac mac;


    nexus_metadata_get_mac(metadata, &mac);


    if (stashed_item == NULL) {
        stashed_item = nexus_malloc(sizeof(struct stashv_item));

        nexus_uuid_copy(&metadata->uuid, &stashed_item->uuid);
        nexus_mac_copy(&mac, &stashed_item->mac);
    }

    if (metadata->version > stashed_item->version) {
        stashed_item->version = metadata->version;

        return __flush_stash_item(&metadata->uuid, &mac, metadata->version);
    }

    return 0;
}


int
stashv_verify(struct nexus_metadata * metadata)
{
    struct nexus_mac stashed_mac;
    struct nexus_mac metadata_mac;

    uint32_t         stashed_version;


    if (__fetch_stash_item(&metadata->uuid, &stashed_mac, &stashed_version)) {
        return stashv_update(metadata);
    }


    nexus_metadata_get_mac(metadata, &metadata_mac);

    if (nexus_mac_compare(&stashed_mac, &metadata_mac) == 0) {
        return 0;
    }

    if (metadata->version > stashed_version) {
        return stashv_update(metadata);
    }

    log_error("metadata is stale. stashv=%zu, metadata_version=%zu\n",
              stashed_version,
              metadata->version);

    return -1;
}
