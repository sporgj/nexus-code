#pragma once
#include <sgx_spinlock.h>

#include <stdbool.h>

#include <nexus_uuid.h>

#include "dirnode.h"
#include "filenode.h"


struct nexus_dentry;


typedef enum {
    NEXUS_SUPERNODE,
    NEXUS_DIRNODE,
    NEXUS_FILENODE
} nexus_metadata_type_t;


struct nexus_metadata {
    struct nexus_uuid            uuid;

    nexus_metadata_type_t        type;

    nexus_io_flags_t             flags;

    uint32_t                     version;

    size_t                       ref_count;

    bool                         is_dirty;

    bool                         is_invalid;

    bool                         is_locked;

    bool                         is_root_dirnode;


    union {
        struct nexus_supernode   * supernode;
        struct nexus_dirnode     * dirnode;
        struct nexus_filenode    * filenode;
        void                     * object;
    };

    sgx_spinlock_t                 dentry_lock;
    struct list_head               dentry_list;
    size_t                         dentry_count;
};


void
__metadata_set_clean(struct nexus_metadata * metadata);

void
__metadata_set_dirty(struct nexus_metadata * metadata);

struct nexus_dentry *
metadata_get_dentry(struct nexus_metadata * metadata);


void
nexus_metadata_get_mac(struct nexus_metadata * metadata, struct nexus_mac * mac_out);

/**
 * Creates a new metadata
 * @param uuid
 * @param obj
 * @param type
 * @return metadata
 */
struct nexus_metadata *
nexus_metadata_from_object(struct nexus_uuid     * uuid,
                           void                  * obj,
                           nexus_metadata_type_t   type,
                           nexus_io_flags_t        flags,
                           uint32_t                version);

struct nexus_metadata *
nexus_metadata_create(struct nexus_uuid * uuid, nexus_dirent_type_t dirent_type);

/**
 * Increments the refcount of the metadata object
 * @param metadata
 * @return the passed metadata object
 */
struct nexus_metadata *
nexus_metadata_get(struct nexus_metadata * metadata);

/**
 * Decrements the ref count of the metadata object
 * @param metadata
 */
void
nexus_metadata_put(struct nexus_metadata * metadata);

/**
 * Frees allocated metadata
 * @param metadata
 */
void
nexus_metadata_free(struct nexus_metadata * metadata);

/**
 * Reloads the metadata from the datastore (usually called after revalidation)
 * @return 0 on success
 */
int
nexus_metadata_reload(struct nexus_metadata * metadata, nexus_io_flags_t flags);

/**
 * Loads the metadata from the specified UUID
 * @param uuid
 * @param type
 * @param mode
 * @return metadata
 */
struct nexus_metadata *
nexus_metadata_load(struct nexus_uuid * uuid, nexus_metadata_type_t type, nexus_io_flags_t mode);

/**
 * Flushes the contents of the metadata to the datastore
 * @param metadata
 * @return 0 on success
 */
int
nexus_metadata_store(struct nexus_metadata * metadata);

int
__nexus_metadata_store(struct nexus_metadata * metadata, struct nexus_mac * mac);

/**
 * Unlocks a locked metadata file
 */
void
nexus_metadata_unlock(struct nexus_metadata * metadata);
