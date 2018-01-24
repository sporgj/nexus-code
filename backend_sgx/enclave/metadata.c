#include "internal.h"

struct nexus_crypto_buf *
metadata_open(struct nexus_uuid       * uuid,
              struct nexus_uuid_path  * uuid_path)
{
    struct nexus_crypto_buf * crypto_buf         = NULL;

    struct nexus_uuid       * buffer_uuid        = NULL;

    int err = -1;


    err = ocall_metadata_get(&buffer_uuid, uuid, NULL, global_backend_ext);
    if (err || buffer_uuid == NULL) {
        log_error("ocall_metadata_get FAILED\n");
        return NULL;
    }

    // create the crypto buf and return to the user
    crypto_buf = nexus_crypto_buf_create(buffer_uuid);
    if (crypto_buf == NULL) {
        log_error("nexus_crypto_buf_create FAILED\n");
        goto cleanup;
    }

    return crypto_buf;
cleanup:
    if (buffer_uuid) {
        ocall_buffer_free(buffer_uuid);
    }

    return NULL;
}

int
metadata_write(struct nexus_uuid       * uuid,
               struct nexus_uuid_path  * uuid_path,
               struct nexus_crypto_buf * crypto_buffer)
{
    int ret = -1;

    ret = nexus_crypto_buf_flush(crypto_buffer, uuid, NULL);

    if (ret) {
        log_error("nexus_crypto_buf_flush FAILED\n");
        return -1;
    }

    return 0;
}

