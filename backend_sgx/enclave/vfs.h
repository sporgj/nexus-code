#pragma once

#include <nexus_list.h>
#include <nexus_fs.h>
#include <nexus_hash.h>

#include "metadata.h"



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
 * puts back a metadata onto the VFS. If dirty, metadata will be flushed
 * @param metadata
 * @return -1 if flushing metadata failed.
 */
int
nexus_vfs_put(struct nexus_metadata * metadata);

/**
 * Drops the metadata out of the VFS.
 */
void
nexus_vfs_drop(struct nexus_metadata * metadata);

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

