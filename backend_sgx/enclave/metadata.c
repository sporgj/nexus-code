#include "internal.h"

#if 0
struct metadata *
metadata_new(struct nexus_uuid * uuid)
{
    struct metadata * metadata = NULL;

    // allocate a new metadata object

    // copy uuid into the metadata uuid

    return metadata;
}
#endif

struct crypto_buffer *
metadata_open(struct nexus_uuid       * uuid,
              struct nexus_uuid_path  * uuid_path,
              void                   ** decrypted_metadata_contents,
              crypto_mac_t            * mac)
{
    struct crypto_buffer    * crypto_buffer  = NULL;

    struct nexus_uuid_path  * untrusted_path = NULL;

    int err = -1;
    int ret = -1;


    // invoke the ocall to get metadata contents
    err = ocall_metadata_get(&crypto_buffer,
                             uuid,
                             untrusted_path,
                             global_backend_ext);

    if (err || ret) {
        ocall_debug("ocall_metadata_get FAILED");
        goto out;
    }


    ret = 0;
out:
    if (untrusted_path) {
        free(untrusted_path);
    }

    if (ret) {
        if (crypto_buffer) {
            crypto_buffer_free(crypto_buffer);
        }

        return NULL;
    }

    return crypto_buffer;
}

int
metadata_write(struct nexus_uuid      * uuid,
               struct nexus_uuid_path * uuid_path,
               struct crypto_buffer   * crypto_buffer)
{
    int err = -1;
    int ret = -1;

    // TODO

    ret = 0;
out:
    return ret;
}

