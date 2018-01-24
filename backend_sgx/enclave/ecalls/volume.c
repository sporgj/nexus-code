#include "../internal.h"

static int
nx_create_volume(char * user_pubkey, struct nexus_uuid * supernode_uuid_out)
{
    struct supernode * supernode = NULL;

    int ret = -1;

    // this indirectly creates and stores the root dirnode
    supernode = supernode_create(user_pubkey);
    if (!supernode) {
        log_error("supernode_create FAILED");
        goto out;
    }

    ret = supernode_store(supernode, NULL, NULL);
    if (ret) {
        goto out;
    }

    nexus_uuid_copy(&supernode->my_uuid, supernode_uuid_out);

    ret = 0;
out:
    if (supernode) {
        supernode_free(supernode);
    }

    return ret;
}

int
ecall_create_volume(char              * user_pubkey_in,
                    struct nexus_uuid * supernode_uuid_out,
                    struct nexus_uuid * volkey_bufuuid_out)
{
    int ret = -1;


    if (enclave_volumekey_gen()) {
        log_error("could not generate volumekey\n");
        return -1;
    }

    ret = nx_create_volume(user_pubkey_in, supernode_uuid_out);
    if (ret) {
        log_error("nx_create_volume FAILED\n");
        goto out;
    }

    // write out the volumekey
    {
        struct nexus_sealed_buf * sealed_volkey = NULL;

        ret = -1;

        sealed_volkey = enclave_volumekey_serialize();

        if (sealed_volkey) {
            log_error("could not serialize volumekey\n");
            goto out;
        }

        ret = nexus_sealed_buf_flush(sealed_volkey, volkey_bufuuid_out);
        if (ret) {
            nexus_sealed_buf_free(sealed_volkey);
            log_error("could not flush volkey uuid\n");
            goto out;
        }

        // TODO call nexus_sealed_buf_release
    }

    ret = 0;
out:
    enclave_volumekey_clear();

    return ret;
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
