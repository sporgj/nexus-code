#include "internal.h"

struct metadata *
metadata_new(struct nexus_uuid * uuid)
{
    struct metadata * metadata = NULL;

    // allocate a new metadata object

    // copy uuid into the metadata uuid

    return metadata;
}

struct metadata *
metadata_open(struct nexus_uuid       * uuid,
              struct nexus_uuid_path  * uuid_path,
              void                   ** p_metadata_object)
{
    struct metadata * metadata = NULL;

    struct nexus_uuid_path  * untrusted_path   = NULL;

    struct nexus_raw_buffer * untrusted_buffer = NULL;

    int err = -1;
    int ret = -1;

    // copy the uuid into untrusted memory

    // invoke the ocall metadata
    err = ocall_metadata_get(
        &ret, uuid, untrusted_path, &untrusted_buffer, global_backend_ext);

    if (err || ret) {
        ocall_debug("ocall_metadata_get FAILED");
        goto out;
    }

    ret = 0;
out:
    if (ret) {
        // free everything here

        return NULL;
    }

    return metadata;
}

int
metadata_write(struct metadata * metadata,
               void            * metadata_object,
               size_t            buflen)
{
    // deallocate previous interna
    return -1;
}

int
metadata_flush(struct metadata * metadata)
{
    // TODO
    return -1;
}

void
metadata_close(struct metadata * metadata)
{
    // TODO
}
