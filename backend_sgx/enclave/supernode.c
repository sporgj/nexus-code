#include "internal.h"

static struct supernode *
supernode_new(struct raw_buffer * user_pubkey)
{
    struct supernode * supernode = NULL;

    supernode = nexus_malloc(sizeof(struct supernode));

    nexus_uuid_gen(&supernode->my_uuid);
    nexus_uuid_gen(&supernode->root_uuid);
    nexus_uuid_gen(&supernode->user_list_uuid);

    return supernode;
}

struct supernode *
supernode_create(struct raw_buffer * user_pubkey, struct nexus_key * volumekey)
{
    struct supernode * supernode = NULL;

    int ret = -1;


    supernode = supernode_new(user_pubkey);
    if (supernode == NULL) {
        return NULL;
    }

    // user table
#if 0
    {
        struct volume_usertable * usertable = NULL;

        usertable = volume_usertable_create(&supernode->user_list_uuid);
        if (usertable == NULL) {
            goto out;
        }

        ret = volume_usertable_store(usertable, &supernode->user_list_mac);

        volume_usertable_free(usertable);

        if (ret != 0) {
            ocall_debug("volume_usertable_store FAILED");
            goto out;
        }
    }
#endif

    // dirnode
    {
        struct dirnode * root_dirnode = dirnode_create(&supernode->root_uuid);
        if (root_dirnode == NULL) {
            ret = -1;
            goto out;
        }

        nexus_uuid_copy(&root_dirnode->root_uuid, &root_dirnode->my_uuid);

        ret = dirnode_store(root_dirnode, NULL, volumekey, NULL);

        dirnode_free(root_dirnode);

        if (ret != 0) {
            log_error("dirnode_store FAILED\n");
            goto out;
        }
    }

    ret = 0;
out:
    if (ret) {
        supernode_free(supernode);
        return NULL;
    }

    return supernode;
}

static void *
supernode_serialize(struct supernode * supernode, size_t * p_size)
{
    // TODO
    *p_size = sizeof(struct supernode);
    return supernode;
}


int
supernode_store(struct supernode       * supernode,
                struct nexus_uuid_path * uuid_path,
                struct nexus_key       * volumekey,
                struct nexus_mac       * mac)
{
    struct nexus_crypto_buf * crypto_buffer = NULL;

    uint8_t * serialized_buffer = NULL;
    size_t    serialized_buflen = 0;

    int ret = -1;


    // for now, we just serialize the dirnode into a static buffer
    serialized_buffer = supernode_serialize(supernode, &serialized_buflen);
    if (!serialized_buffer) {
        return -1;
    }

    // allocates the crypto buffer
    crypto_buffer = nexus_crypto_buf_new(serialized_buflen);
    if (!crypto_buffer) {
        goto out;
    }

    ret = nexus_crypto_buf_put(crypto_buffer, serialized_buffer, mac);

    if (ret) {
        log_error("crypto_buffer_write\n");
        goto out;
    }

    // write it to the datastore
    ret = metadata_write(&supernode->my_uuid, uuid_path, crypto_buffer);
    if (ret) {
        log_error("metadata_write failed\n");
    }

    ret = 0;
out:
    if (crypto_buffer) {
        nexus_crypto_buf_free(crypto_buffer);
    }

    return ret;
}

void
supernode_free(struct supernode * supernode)
{
    // TODO
}
