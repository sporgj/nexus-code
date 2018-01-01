#include "internal.h"

static struct supernode *
supernode_new(struct nexus_raw_key * user_pubkey)
{
    struct supernode * supernode = NULL;

    supernode = (struct supernode *)calloc(1, sizeof(struct supernode));

    if (supernode == NULL) {
        ocall_debug("allocation error");
        return NULL;
    }

    nexus_uuid_gen(&supernode->my_uuid);
    nexus_uuid_gen(&supernode->root_uuid);

    crypto_sha256(
        user_pubkey->key_data, user_pubkey->key_size, supernode->owner_pubkey);

    return supernode;
}

struct supernode *
supernode_create(struct nexus_raw_key * user_pubkey)
{
    struct supernode * supernode = NULL;

    crypto_mac_t usertable_mac = { 0 };

    int ret = -1;


    supernode = supernode_new(user_pubkey);
    if (supernode == NULL) {
        return NULL;
    }

    // user table
    {
        struct volume_usertable * usertable = NULL;

        usertable = volume_usertable_create(&supernode->user_list_uuid);
        if (usertable == NULL) {
            goto out;
        }

        ret = volume_usertable_store(usertable, &usertable_mac);

        volume_usertable_free(usertable);

        if (ret != 0) {
            ocall_debug("volume_usertable_store FAILED");
            goto out;
        }
    }

    // dirnode
    {
        struct dirnode * root_dirnode = dirnode_create(&supernode->root_uuid);
        if (root_dirnode == NULL) {
            goto out;
        }

        nexus_uuid_copy(&root_dirnode->my_uuid, &root_dirnode->root_uuid);

        ret = dirnode_store(root_dirnode, NULL, NULL);

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

void
supernode_free(struct supernode * supernode)
{
    // TODO
}
