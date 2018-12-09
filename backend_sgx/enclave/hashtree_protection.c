/*
 * Responsible for maintaining merkle hash tree
 */

#include "metadata.h"
#include "dentry.h"
#include "enclave_internal.h"


static struct nexus_mac hashtree_root_mac = { 0 };

static uint32_t         hashtree_root_version;



static int
__fetch_hashtree_root()
{
    int err = -1;
    int ret = -1;

    err = ocall_hashtree_fetch_root(&ret, &hashtree_root_version, &hashtree_root_mac, global_volume);

    if (err || ret) {
        log_error("ocall_hashtree_fetch_root FAILED (err=%d, ret=%d)\n", err, ret);
        return -1;
    }

    return 0;
}

static int
__store_hashtree_root()
{
    int err = -1;
    int ret = -1;

    err = ocall_hashtree_store_root(&ret, &hashtree_root_version, &hashtree_root_mac, global_volume);

    if (err || ret) {
        log_error("ocall_hashtree_store_root FAILED (err=%d, ret=%d)\n", err, ret);
        return -1;
    }

    return 0;
}

static int
__update_hashtree_root(struct nexus_metadata * root_metadata)
{
    if (hashtree_root_version == root_metadata->version) {
        return 0;
    }

    nexus_metadata_get_mac(root_metadata, &hashtree_root_mac);

    hashtree_root_version = root_metadata->version;

    return __store_hashtree_root();
}


int
hashtree_init()
{
    if (__fetch_hashtree_root()) {
        log_error("__fetch_hashtree_root() FAILED\n");
        return -1;
    }

    return 0;
}

void
hashtree_destroy()
{
    //
}

int
hashtree_update(struct nexus_dentry * parent_dentry,
                struct nexus_uuid   * child_uuid,
                struct nexus_mac    * child_mac)
{
    struct nexus_dirnode * dirnode = NULL;

    int ret = -1;


    if (parent_dentry == NULL) {
        return 0;
    }

    if (parent_dentry->metadata == NULL) {
        log_error("dentry does not have a metadata object to update");
        return -1;
    }

    // update the child mac in the dirnode
    dirnode = parent_dentry->metadata->dirnode;

    if (dirnode_update_direntry_mac(dirnode, child_uuid, child_mac)) {
        log_error("could not update direntry\n");
        return -1;
    }

    ret = nexus_metadata_store(parent_dentry->metadata);

    if (ret == 0 && parent_dentry == root_dentry) {
        ret = __update_hashtree_root(&parent_dentry->metadata);
    }

    return ret;
}

int
hashtree_verify(struct nexus_dentry * dentry)
{
    struct nexus_metadata * metadata = dentry->metadata;

    struct nexus_dirnode * parent_dirnode = NULL;

    struct nexus_mac metadata_mac;


    if (metadata == NULL) {
        log_error("dentry is invalid for merkle validation\n");
        return -1;
    }

    // if it's the root, let's make sure we have the latest version
    if (dentry == root_dentry) {
        if (hashtree_root_version > metadata->version) {
            log_error("metadata version out of date. local=%zu, remote=%zu\n",
                      (size_t) hashtree_root_version,
                      (size_t) metadata->version);
            return -1;
        }

        return __update_hashtree_root(metadata);
    }

    if (dentry->parent->metadata == NULL) {
        log_error("parent dentry cannot be NULL\n");
        return -1;
    }

    parent_dirnode = dentry->parent->metadata->dirnode;

    nexus_metadata_get_mac(metadata, &metadata_mac);

    // otherwise, just check with the parent dirnode
    return dirnode_check_direntry_mac(parent_dirnode, &metadata->uuid, &metadata_mac);
}
