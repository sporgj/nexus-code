#include "internal.h"


struct dirnode *
dirnode_create(struct nexus_uuid * root_uuid)
{
    struct dirnode * dirnode = NULL;

    dirnode = nexus_malloc(sizeof(struct dirnode));

    nexus_uuid_gen(&dirnode->my_uuid);
    nexus_uuid_copy(root_uuid, &dirnode->root_uuid);


    return dirnode;
}

static void *
dirnode_serialize(struct dirnode * dirnode, size_t * p_size)
{
    // TODO
    *p_size = sizeof(struct dirnode);
    return dirnode;
}

int
dirnode_store(struct dirnode         * dirnode,
              struct nexus_uuid_path * uuid_path,
              struct nexus_mac       * mac)
{
    struct nexus_crypto_buf * crypto_buffer = NULL;

    uint8_t * serialized_buffer = NULL;
    size_t    serialized_buflen = 0;

    int ret = -1;


    // for now, we just serialize the dirnode into a static buffer
    serialized_buffer = dirnode_serialize(dirnode, &serialized_buflen);
    if (!serialized_buffer) {
        return -1;
    }

    // allocate the crypto buffer
    crypto_buffer = nexus_crypto_buf_new(serialized_buflen);
    if (!crypto_buffer) {
        goto out;
    }

    // write to the buffer
    {
        uint8_t * output_buffer = NULL;

        size_t    buffer_size   = 0;


        output_buffer = nexus_crypto_buf_get(crypto_buffer, &buffer_size, NULL);

        if (output_buffer == NULL) {
            log_error("could not get the crypto_bufffer buffer\n");
            goto out;
        }

        memcpy(output_buffer, serialized_buffer, serialized_buflen);

        ret = nexus_crypto_buf_put(crypto_buffer, mac);

        if (ret) {
            log_error("nexus_crypto_buf_put FAILED\n");
            goto out;
        }
    }

    // flush the buffer to the backend
    ret = metadata_write(&dirnode->my_uuid, uuid_path, crypto_buffer);
    if (ret) {
        log_error("metadata_write FAILED\n");
        goto out;
    }

    ret = 0;
out:
    if (crypto_buffer) {
        nexus_crypto_buf_free(crypto_buffer);
    }

    return ret;
}

void
dirnode_free(struct dirnode * dirnode)
{
    nexus_free(dirnode);
}
