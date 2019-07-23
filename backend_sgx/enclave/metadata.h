#pragma once
#include <sgx_spinlock.h>

#include <stdbool.h>

#include <nexus_uuid.h>

#include "dirnode.h"
#include "filenode.h"
#include "supernode.h"

#include "abac/nexus_abac.h"

struct nexus_dentry;


typedef enum {
    NEXUS_SUPERNODE,
    NEXUS_DIRNODE,
    NEXUS_FILENODE,
    NEXUS_HARDLINK_TABLE,

    NEXUS_USER_TABLE,

    NEXUS_ATTRIBUTE_STORE,
    NEXUS_POLICY_STORE,
    NEXUS_USER_PROFILE,
    NEXUS_AUDIT_LOG,
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

    union {
        struct nexus_supernode   * supernode;
        struct nexus_dirnode     * dirnode;
        struct nexus_filenode    * filenode;

        struct hardlink_table    * hardlink_table;

        struct nexus_usertable   * user_table;

        struct attribute_space   * attribute_space;
        struct policy_store      * policy_store;
        struct user_profile      * user_profile;
        struct audit_log         * audit_log;

        void                     * object;
    };

    struct nexus_metadata        * audit_log_metadata; // set by the abac runtime

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

struct attribute_table *
metadata_get_attribute_table(struct nexus_metadata * metadata);

int
nexus_metadata_export_mac(struct nexus_metadata * metadata, struct nexus_mac * mac);

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
nexus_metadata_create(struct nexus_uuid * uuid, nexus_metadata_type_t metadata_type);

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

int
nexus_metadata_revalidate(struct nexus_metadata * metadata,
                          nexus_io_flags_t        flags,
                          bool                  * has_changed);

/**
 * Reloads the metadata from the datastore (usually called after revalidation)
 * @return 0 on success
 */
int
nexus_metadata_reload(struct nexus_metadata * metadata, nexus_io_flags_t flags);

void
nexus_metadata_reset(struct nexus_metadata * metadata);

/**
 * Loads the metadata from the specified UUID
 * @param uuid
 * @param type
 * @param mode
 * @return metadata
 */
struct nexus_metadata *
nexus_metadata_load(struct nexus_uuid * uuid, nexus_metadata_type_t type, nexus_io_flags_t flags);

/**
 * Flushes the contents of the metadata to the datastore
 * @param metadata
 * @return 0 on success
 */
int
nexus_metadata_store(struct nexus_metadata * metadata);

int
nexus_metadata_lock(struct nexus_metadata * metadata, nexus_io_flags_t flags);

/**
 * Unlocks a locked metadata file
 */
void
nexus_metadata_unlock(struct nexus_metadata * metadata);

int
nexus_metadata_verify_uuids(struct nexus_dentry * dentry);


bool
nexus_metadata_has_changed(struct nexus_metadata * metadata);

int
metadata_create_audit_log(struct nexus_metadata * metadata);

struct nexus_metadata *
metadata_get_audit_log(struct nexus_metadata * metadata, nexus_io_flags_t flags);

bool
metadata_has_audit_log(struct nexus_metadata * metadata);
