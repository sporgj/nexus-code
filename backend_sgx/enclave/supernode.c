#include "internal.h"

static struct supernode *
supernode_new(struct raw_buffer * user_pubkey)
{
    struct supernode * supernode = NULL;

    supernode = nexus_malloc(sizeof(struct supernode));

    nexus_uuid_gen(&supernode->my_uuid);
    nexus_uuid_gen(&supernode->root_uuid);
    nexus_uuid_gen(&supernode->user_list_uuid);

    crypto_sha256(raw_buffer_get(user_pubkey),
                  user_pubkey->size,
                  supernode->owner_pubkey);

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
            goto out;
        }

        nexus_uuid_copy(&root_dirnode->root_uuid, &root_dirnode->my_uuid);

        ret = dirnode_store(root_dirnode, NULL, volumekey, NULL);

        dirnode_free(root_dirnode);

        if (ret != 0) {
            ocall_debug("dirnode_store FAILED");
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
                crypto_mac_t           * mac)
{
    struct crypto_buffer * crypto_buffer = NULL;

    uint8_t * serialized_buffer = NULL;
    size_t    serialized_buflen = 0;

    int ret = -1;


    // for now, we just serialize the dirnode into a static buffer
    serialized_buffer = supernode_serialize(supernode, &serialized_buflen);
    if (!serialized_buffer) {
        return -1;
    }

    // allocate the crypto buffer
    crypto_buffer = crypto_buffer_new(serialized_buflen);
    if (!crypto_buffer) {
        goto out;
    }

    ret = crypto_buffer_write(crypto_buffer,
                              &supernode->my_uuid,
                              serialized_buffer,
                              serialized_buflen,
                              mac);

    if (ret) {
        ocall_debug("crypto_buffer_write");
        goto out;
    }

    // write it to the datastore
    ret = metadata_write(&supernode->my_uuid, uuid_path, crypto_buffer);
    if (ret) {
        ocall_debug("metadata_write failed");
    }

    ret = 0;
out:
    if (crypto_buffer) {
        crypto_buffer_free(crypto_buffer);
    }

    return ret;
}

void
supernode_free(struct supernode * supernode)
{
    // TODO
}
