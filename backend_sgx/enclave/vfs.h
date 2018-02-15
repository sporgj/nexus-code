#pragma once

#include <nexus_hash.h>

#include "dirnode.h"
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
 * Verifies that the user's public key can be found in the usertable
 * @param user_pubkey_hash
 * @return 0 on success
 */
int
nexus_vfs_verfiy_pubkey(struct nexus_hash * user_pubkey_hash);

/**
 * Converts a path into a metadata object
 * @param path
 * @return metadata
 */
struct nexus_metadata *
nexus_vfs_get(char * path, nexus_metadata_type_t type);

/**
 * Returns a path onto the VFS
 * @param metadata
 */
void
nexus_vfs_put(struct nexus_metadata * metadata);

/**
 * Flushes the content of the metadata back to the backing store
 * @param metadata
 */
int
nexus_vfs_flush(struct nexus_metadata * metadata);

/**
 * Loads a metadata object from the buffer layer
 * @param metadata_uuid
 * @param uuid_path
 */
struct nexus_metadata *
nexus_vfs_load(struct nexus_uuid * metadata_uuid, struct nexus_uuid_path * uuid_path);
