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

    err = ocall_hashtree_store_root(&ret, hashtree_root_version, &hashtree_root_mac, global_volume);

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
hashtree_update(struct nexus_metadata * metadata)
{
    struct nexus_dentry * parent_dentry = NULL;
    struct nexus_dentry * child_dentry  = NULL;

    struct nexus_mac    child_mac;
    struct nexus_uuid * child_uuid = NULL;



    if (metadata->is_root_dirnode) {
        return __update_hashtree_root(metadata);
    }

    // as of now, we assume hardlink files will be in the same directory as the parent.
    // this will SURELY change in the next update

    child_dentry = metadata_get_dentry(metadata);

    if (child_dentry == NULL) {
        return 0;
    }


    parent_dentry = child_dentry->parent;

    nexus_metadata_get_mac(metadata, &child_mac);

    child_uuid = &child_dentry->metadata->uuid;

    do {
        if (parent_dentry->metadata == NULL) {
            log_error("parent dentry (%s) does not have a metadata object\n", parent_dentry->name);
            return -1;
        }


        struct nexus_dirnode * parent_dirnode = parent_dentry->metadata->dirnode;

        if (dirnode_hashtree_update(parent_dirnode, child_uuid, &child_mac, metadata->version)) {
            log_error("could not update direntry\n");
            return -1;
        }

        if (__nexus_metadata_store(parent_dentry->metadata, &child_mac)) {
            log_error("__nexus_metadata_store() FAILED\n");
            return -1;
        }


        child_dentry = parent_dentry;
        child_uuid = &child_dentry->metadata->uuid;
        parent_dentry = parent_dentry->parent;
    } while(child_dentry != global_root_dentry);


    return __update_hashtree_root(global_root_dentry->metadata);
}

int
hashtree_verify(struct nexus_dentry * dentry)
{
    struct nexus_metadata * metadata = dentry->metadata;

    struct nexus_dirnode * parent_dirnode = NULL;

    struct nexus_mac metadata_mac;
    struct nexus_mac link_mac;

    uint32_t link_version = 0;


    if (metadata == NULL) {
        log_error("dentry is invalid for merkle validation\n");
        return -1;
    }

    // if it's the root, let's make sure we have the latest version
    if (dentry == global_root_dentry) {
        if (hashtree_root_version > metadata->version) {
            log_error("root metadata outdated. local=%zu, remote=%zu\n",
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
    if (dirnode_hashtree_fetch(parent_dirnode, &metadata->uuid, &link_mac, &link_version)) {
        log_error("dirnode_hashtree_fetch FAILED\n");
        return -1;
    }

    if (nexus_mac_compare(&metadata_mac, &link_mac) == 0) {
        return 0;
    }

    // if it's a file, there's a chance it was updated through another link (they can have multiple parents)
    if (metadata->type == NEXUS_FILENODE && metadata->version > link_version) {
        // XXX: to be strictly secure, we should probably have the parent dirnode updated with this filenode
        // but i presume this will be updated soon on this tree.
        return 0;
    }

    log_error("'%s' metadata is stale (link_version=%zu, metadata_version=%zu)\n",
              dentry->name,
              (size_t)link_version,
              (size_t)metadata->version);

    return -1;
}
