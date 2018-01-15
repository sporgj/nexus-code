#include "internal.h"

// TODO move this to nexus_key
#define VOLUMEKEY_SIZE_BYTES    128

static int
nx_create_volume(struct raw_buffer * user_pubkey,
                 struct nexus_uuid * supernode_uuid_out,
                 struct nexus_key ** p_volumekey)
{
    struct supernode * supernode = NULL;

    struct nexus_key * volumekey = NULL;

    int ret = -1;


    // generate the volumekey
    volumekey = nexus_create_key(NEXUS_RAW_128_KEY);
    if (!volumekey) {
        ocall_debug("nexus_create_key FAILED");
        return -1;
    }

    supernode = supernode_create(user_pubkey, volumekey);
    if (!supernode) {
        ocall_debug("supernode_create FAILED");
        goto out;
    }

    ret = supernode_store(supernode, NULL, volumekey, NULL);
    if (ret) {
        goto out;
    }


    *p_volumekey = volumekey;
    nexus_uuid_copy(&supernode->my_uuid, supernode_uuid_out);

    ret = 0;
out:
    if (supernode) {
        supernode_free(supernode);
    }

    if (ret) {
        nexus_free_key(volumekey);
    }

    return ret;
}

int
ecall_create_volume(struct raw_buffer  * user_pubkey_in,
                    struct nexus_uuid  * supernode_uuid_out,
                    struct raw_buffer ** sealed_volumekey_out)
{
    struct nexus_key * volumekey = NULL;

    int ret = -1;


    ret = nx_create_volume(user_pubkey_in, supernode_uuid_out, &volumekey);
    if (ret) {
        ocall_debug("nx_create_volume FAILED");
        return -1;
    }

#if 0
    // seal the volumekey and return to untrusted memory
    *sealed_volumekey_out = sealed_buffer_write(volumekey->key,
                                                VOLUMEKEY_SIZE_BYTES);
#endif

    nexus_free_key(volumekey);

    if (*sealed_volumekey_out == NULL) {
        return -1;
    }

    return 0;
}


#if 0
int
ecall_auth_request(struct raw_buffer *    user_pubkey_in,
                   struct sealed_buffer * sealed_volkey_in,
                   struct raw_buffer **   nonce_challenge_out)
{
    // TODO
    return -1;
}

int
ecall_auth_response(struct crypto_buffer * supernode_in,
                    struct raw_buffer *    signature_in)
{
    // TODO
    return -1;
}
#endif
