#include "enclave_internal.h"

int
nexus_vfs_init(struct nexus_crypto_buf * crypto_buf)
{
    uint8_t * buffer = NULL;
    size_t    buflen = 0;


    buffer = nexus_crypto_buf_get(crypto_buf, &buflen, NULL);
    if (buffer == NULL) {
        log_error("nexus_crypto_buf_get() FAILED\n");
        return -1;
    }

    global_supernode = supernode_from_buffer(buffer, buflen);

    return 0;
}

int
nexus_vfs_verfiy_pubkey(struct nexus_hash * user_pubkey_hash)
{
    // TODO add code that iterates through user names in the supernode's usertable
    return nexus_hash_compare(&global_supernode->owner_pubkey_hash, user_pubkey_hash);
}

void
nexus_vfs_exit()
{
    supernode_free(global_supernode);
    global_supernode = NULL;
}
