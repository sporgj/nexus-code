#pragma once

#include <nexus_list.h>
#include <nexus_fs.h>
#include <nexus_hash.h>

#include "metadata.h"
#include "dentry.h"


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
 * Converts a path into a metadata object
 * @param path
 * @param dentry is the dentry corresponding to this path
 * @return metadata
 */
struct nexus_metadata *
nexus_vfs_get(char * path, nexus_io_flags_t flags);

// lookup the dentry
struct nexus_dentry *
nexus_vfs_lookup(char * filepath);

struct nexus_dentry *
nexus_vfs_lookup_parent(char * filepath, struct path_walker * walker);

struct nexus_metadata *
nexus_vfs_complete_lookup(struct path_walker * walker, nexus_io_flags_t flags);

/**
 * puts back a metadata onto the VFS
 * @param metadata
 */
void
nexus_vfs_put(struct nexus_metadata * metadata);

/**
 * Checks whether the specified metadata object is uptodate
 * @param metadata
 * @return 0 on success
 */
int
nexus_vfs_revalidate(struct nexus_metadata * metadata, nexus_io_flags_t flags, bool * has_changed);

int
__vfs_revalidate(struct nexus_metadata * metadata, nexus_io_flags_t flags, bool * has_changed);


struct nexus_supernode *
nexus_vfs_acquire_supernode(nexus_io_flags_t flags);


void
nexus_vfs_release_supernode();


struct hardlink_table *
nexus_vfs_acquire_hardlink_table(nexus_io_flags_t flags);

int
nexus_vfs_flush_hardlink_table();

void
nexus_vfs_release_hardlink_table();


struct nexus_usertable *
nexus_vfs_acquire_user_table(nexus_io_flags_t flags);

int
nexus_vfs_flush_user_table();

void
nexus_vfs_release_user_table();

/**
 * Loads a metadata object from the buffer layer
 * @param metadata_uuid
 * @param uuid_path
 */
struct nexus_metadata *
nexus_vfs_load(struct nexus_uuid     * metadata_uuid,
               nexus_metadata_type_t   metadata_type,
               nexus_io_flags_t         flags );

void
nexus_vfs_delete(struct nexus_uuid * metadata_uuid);


struct nexus_metadata *
dentry_get_metadata(struct nexus_dentry * dentry, nexus_io_flags_t flags, bool revalidate);
