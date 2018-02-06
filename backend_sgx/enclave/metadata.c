#include "enclave_internal.h"

struct nexus_crypto_buf *
metadata_read(struct nexus_uuid       * uuid,
              struct nexus_uuid_path  * uuid_path)
{
    struct nexus_crypto_buf * crypto_buf           = NULL;

    struct nexus_uuid       * buffer_uuid          = NULL;
    struct nexus_uuid       * buffer_uuid_internal = NULL;

    int err = -1;


    err = ocall_metadata_get(&buffer_uuid, uuid, NULL, global_backend_ext);
    if (err || buffer_uuid == NULL) {
        log_error("ocall_metadata_get FAILED (err=%d)\n", err);
        return NULL;
    }

    // without copying this within the enclave, every ocall using this
    // pointer will fail pointer checks.
    buffer_uuid_internal = nexus_uuid_clone(buffer_uuid);

    crypto_buf = nexus_crypto_buf_create(buffer_uuid_internal);


    if (crypto_buf == NULL) {
        ocall_buffer_put(buffer_uuid_internal, global_backend_ext);
        nexus_free(buffer_uuid_internal);

        log_error("nexus_crypto_buf_create FAILED\n");
        return NULL;
    }

    nexus_free(buffer_uuid_internal);

    return crypto_buf;
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

