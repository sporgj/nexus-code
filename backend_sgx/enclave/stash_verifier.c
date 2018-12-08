
/* Responsible for verifying the returned file versions */

#include <nexus_hashtable.h>
#include "enclave_internal.h"

#define HASHTABLE_SIZE 127

typedef enum {
    NEXUS_STASH_UPDATE = 0,
    NEXUS_STASH_REMOVE = 1,
    NEXUS_STASH_ADD    = 2
} nexus_dentry_type_t;

struct stash_verifier * stashv;

struct stash_verifier {
    struct nexus_hashtable * stash_table;

    size_t table_size;
};

/* 
 * Initialize the stash verifier, loads the stash file
 * of the volume from untrusted memory
 */
int
stashv_init(struct nexus_uuid *vol_ptr) {

    if (vol_ptr != NULL) {
        
        int err = -1;
        int ret = -1;

        err = ocall_stash_init(&ret, vol_ptr);

        if (err || ret) {
            log_error("stashv_init FAILED (err=%d, ret=%d)\n", err, ret);
            return -1;
        }
        
        stashv = nexus_malloc(sizeof (struct stash_verifier));
        
        stashv->table_size = HASHTABLE_SIZE;
        
        stashv->stash_table = nexus_malloc(stashv->table_size);
        
        if (stashv->stash_table == NULL) {
            nexus_free(stashv);
            log_error("nexus_create_htable FAILED\n");
            return -1;
        }
        
        stashv->stash_table = nexus_create_htable(HASHTABLE_SIZE,
                __uuid_hasher,
                __uuid_equals);
    } else {
        //need volume info
        log_error("stashv_init FAILED\n");
        return -1;
    }
    return 0;
}

/* 
 * Adds a new UUID to the stash file
 * and initializes its version to 0
 */
int
stashv_add(struct nexus_uuid *uuid) {

    nexus_htable_insert(stashv->stash_table, uuid, (uintptr_t) 0);
    if(stashv_flush(NEXUS_STASH_ADD, uuid, NULL) == -1) {
        log_error("stash_flush FAILED\n");
        return -1;
    }
    return 0;
}

/* 
 * Verifies the returned version of the 
 * file with the last seen version and if
 * the returned version if less than the seen
 * version update the stash file
 */
int
stashv_check_update(struct nexus_uuid *uuid, uint32_t version) {

    uint32_t seen_version = nexus_htable_search(stashv->stash_table, uuid);
    if(seen_version == NULL) {
        int err = -1;
        
        uint32_t saved_version = 0;

        //err = ocall_stash_get(&ret, uuid, &saved_version);
        err = ocall_stash_get(uuid, &saved_version);

        if (err) {
            log_error("stashv_check_update FAILED (err=%d)\n", err);
            return -1;
        }
        
        seen_version = saved_version;
        
        nexus_htable_insert(stashv->stash_table, uuid, saved_version);
    }
    if (seen_version < version) {
        nexus_htable_insert(stashv->stash_table, uuid, version);
        //table.update(uuid, version);
        if(stashv_flush(NEXUS_STASH_UPDATE, uuid, version) == -1) {
            log_error("stash_flush FAILED\n");
            return -1;
        }
        return 0;
    } else if (seen_version == version) {
        return 0;
    }
    return -1;
}

/* 
 * Deletes an existing UUID from
 * the stash file
 */
int
stashv_delete(struct nexus_uuid *uuid) {

    //What is free key?
    nexus_htable_remove(stashv->stash_table, uuid, 1);
    if(stashv_flush(NEXUS_STASH_REMOVE, uuid, NULL) == -1) {
        log_error("stash_flush FAILED\n");
        return -1;
    }
    return 0;
}

/* 
 * Flushes the current state of the table
 * to stash file
 */
int
stashv_flush(int op, struct nexus_uuid *uuid, uint32_t version) {
    
    int err = -1;
    int ret = -1;
        
    if(op == NEXUS_STASH_ADD) {
        err = ocall_stash_put(&ret, uuid, version);
    } else if(op == NEXUS_STASH_REMOVE) {
        err = ocall_stash_evict(&ret, uuid);
    } else if(op == NEXUS_STASH_UPDATE) {
        err = ocall_stash_put(&ret, uuid, version);
    }

    if (err || ret) {
        log_error("ocall_stash_update FAILED (err=%d, ret=%d)\n", err);
        return -1;
    }
    
    return 0;
}

/* 
 * Exit 
 */
int
stashv_exit() {

    nexus_free_htable(stashv->stash_table, 0, 0);
    nexus_free(stashv);
    return 0;
}