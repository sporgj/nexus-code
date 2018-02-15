#include "enclave_internal.h"

struct nexus_crypto_buf *
metadata_read(struct nexus_uuid * uuid, struct nexus_uuid_path * uuid_path)
{
    struct nexus_crypto_buf * crypto_buf = NULL;

    int err = -1;
    int ret = -1;


    err = ocall_metadata_get(&ret, uuid, NULL, global_backend_ext);
    if (err || ret) {
        log_error("ocall_metadata_get FAILED (err=%d, ret=%d)\n", err, ret);
        return NULL;
    }

    crypto_buf = nexus_crypto_buf_create(uuid);
    if (crypto_buf == NULL) {
        log_error("nexus_crypto_buf_create FAILED\n");
        return NULL;
    }

    return crypto_buf;
}
