#include "internal.h"

struct raw_buffer *
metadata_open(struct nexus_uuid       * uuid,
              struct nexus_uuid_path  * uuid_path)
{
    struct raw_buffer      * raw_buffer_ext = NULL;

    struct nexus_uuid_path * untrusted_path = NULL;

    int ret = -1;


    // invoke the ocall to get metadata contents
    ret = ocall_metadata_get(&raw_buffer_ext,
                             uuid,
                             untrusted_path,
                             global_backend_ext);

    if (ret || raw_buffer == NULL) {
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

    return raw_buffer;
}

int
metadata_write(struct nexus_uuid       * uuid,
               struct nexus_uuid_path  * uuid_path,
               struct nexus_crypto_buf * crypto_buffer)
{
    struct nexus_uuid_path * uuid_path_untrusted = NULL;

    int err = -1;
    int ret = -1;

    err = ocall_metadata_set(&ret,
                             uuid,
                             uuid_path_untrusted,
                             crypto_buffer->untrusted_addr,
                             global_backend_ext);

    if (err || ret) {
        ocall_debug("ocall_metadata_set FAILED");
        return -1;
    }

    return 0;
}

