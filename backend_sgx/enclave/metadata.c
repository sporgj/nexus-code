#include "internal.h"

struct raw_buffer *
metadata_open(struct nexus_uuid       * uuid,
              struct nexus_uuid_path  * uuid_path)
{
#if 0
    struct raw_buffer      * raw_buffer_ext = NULL;

    struct nexus_uuid_path * untrusted_path = NULL;

    int ret = -1;


    // invoke the ocall to get metadata contents
    ret = ocall_metadata_get(&raw_buffer_ext,
                             uuid,
                             untrusted_path,
                             global_backend_ext);

    if (ret || raw_buffer_ext == NULL) {
        ocall_debug("ocall_metadata_get FAILED");
        goto out;
    }


    ret = 0;
out:
    if (untrusted_path) {
        free(untrusted_path);
    }

    if (ret) {
        if (raw_buffer_ext) {
            raw_buffer_free_ext(raw_buffer_ext);
        }

        return NULL;
    }

    return raw_buffer_ext;
#endif
    return NULL;
}

int
metadata_write(struct nexus_uuid       * uuid,
               struct nexus_uuid_path  * uuid_path,
               struct nexus_crypto_buf * crypto_buffer)
{
#if 0
    struct nexus_uuid_path * uuid_path_untrusted = NULL;

    int err = -1;
    int ret = -1;

    err = ocall_metadata_set(&ret,
                             uuid,
                             uuid_path_untrusted,
                             nexus_crypto_buf_untrusted_addr(crypto_buffer),
                             global_backend_ext);

    if (err || ret) {
        ocall_debug("ocall_metadata_set FAILED");
        return -1;
    }

    return 0;
#endif
    return -1;
}

