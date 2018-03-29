#pragma once

#include <nexus_list.h>
#include <nexus_fs.h>
#include <nexus_hash.h>

#include "dirnode.h"

typedef enum {
    NEXUS_DIRNODE,
    NEXUS_FILENODE
} nexus_metadata_type_t;

struct nexus_metadata;


struct nexus_dentry {
    nexus_metadata_type_t metadata_type;

    char * name;
    size_t name_len;

    struct nexus_uuid uuid;

    struct nexus_dentry   * parent;
    struct nexus_metadata * metadata;

    struct list_head children;
    struct list_head siblings;
};


struct nexus_metadata {
    struct nexus_uuid uuid;

    nexus_metadata_type_t type;

    bool is_dirty;

    union {
        struct nexus_dirnode  * dirnode;
        struct nexus_filenode * filenode;
    };

    struct nexus_dentry * dentry;  // dentry pointing to metadata
};




int
nexus_vfs_init();

void
nexus_vfs_deinit();


/**
 * Mounts a supernode unto the VFS
 * @param supernode_crypto_buf
 * @return 0 on success
 */
int
nexus_vfs_mount(struct nexus_crypto_buf * crypto_buf);

/**
 * Verifies that the user's public key can be found in the usertable
 * @param user_pubkey_hash
 * @return 0 on success
 */
int
nexus_vfs_verfiy_pubkey(struct nexus_hash * user_pubkey_hash);


/**
 * Creates a new metadata object
 * @param parent_dentry
 * @param type of metadata
 */
struct nexus_metadata *
nexus_vfs_create(struct nexus_dentry * parent_dentry, nexus_metadata_type_t type);

/**
 * Converts a path into a metadata object
 * @param path
 * @param type the metadata type
 * @param dentry is the dentry corresponding to this path
 * @return metadata
 */
struct nexus_metadata *
nexus_vfs_get(char * path, nexus_metadata_type_t type, struct nexus_dentry ** path_dentry);

/**
 * puts back a metadata onto the VFS
 * @param metadata
 */
void
nexus_vfs_put(struct nexus_metadata * metadata);

/**
 * Drops the metadata out of the VFS.
 */
void
nexus_vfs_drop(struct nexus_metadata * metadata);

/**
 * Flushes the content of the metadata back to the backing store
 * @param metadata
 */
int
nexus_vfs_flush(struct nexus_metadata * metadata);

/**
 * Checks whether the specified metadata object is uptodate
 * @param metadata
 * @return 0 on success
 */
int
nexus_vfs_revalidate(struct nexus_metadata * metadata);



/**
 * Loads a metadata object from the buffer layer
 * @param metadata_uuid
 * @param uuid_path
 */
struct nexus_metadata *
nexus_vfs_load(struct nexus_uuid * metadata_uuid, nexus_metadata_type_t metadata_type);

void
nexus_vfs_delete(struct nexus_uuid * metadata_uuid);



// metadata functions
void
metadata_set_dirty(struct nexus_metadata * metadata, bool dirty);




// dentry functions

/**
 * Performs a dentry lookups
 * @param root_dentry
 * @param path
 */
struct nexus_dentry *
dentry_lookup(struct nexus_dentry * root_dentry, char * path);

void
dentry_delete(struct nexus_dentry * dentry);

void
dentry_delete_child(struct nexus_dentry * parent_dentry, const char * child);


