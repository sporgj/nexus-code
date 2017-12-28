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
              void                   ** decrypted_metadata_contents,
              crypto_mac_t            * mac)
{
    struct metadata        * metadata        = NULL;
    struct metadata_buffer * metadata_buffer = NULL;

    struct nexus_raw_buffer * raw_buffer_ext = NULL;

    uint8_t * encrypted_buffer_ext = NULL;
    uint8_t * decrypted_buffer     = NULL;

    struct nexus_uuid_path * untrusted_path = NULL;

    int ret = -1;



    metadata = (struct metadata *)calloc(1, sizeof(struct metadata));
    if (metadata == NULL) {
        return NULL;
    }

    metadata_buffer = &metadata->metadata_buffer;


    // invoke the ocall to get metadata contents
    {
        int err = ocall_metadata_get(&ret,
                                     uuid,
                                     untrusted_path,
                                     &raw_buffer_ext,
                                     global_backend_ext);

        if (err || ret) {
            ocall_debug("ocall_metadata_get FAILED");
            goto out;
        }

        // copy in the the static data and set the encrypted_buffer_ptr
        memcpy(metadata_buffer,
               raw_buffer_ext->buffer,
               sizeof(struct metadata_buffer));

        encrypted_buffer_ext
            = raw_buffer_ext->buffer + sizeof(struct metadata_buffer);
    }


    decrypted_buffer
        = (uint8_t *)calloc(1, metadata_buffer->header.encrypted_buffer_size);

    if (decrypted_buffer == NULL) {
        ocall_debug("allocation error");
        goto out;
    }


    // decrypt the contents
    {
        ret = crypto_decrypt(&metadata_buffer->crypto_context,
                             metadata_buffer->header.encrypted_buffer_size,
                             encrypted_buffer_ext,
                             decrypted_buffer,
                             mac,
                             (uint8_t *)&metadata_buffer->header,
                             sizeof(struct metadata_header));

        if (ret) {
            ocall_debug("crypto_decrypt FAILED");
            goto out;
        }
    }

    memcpy(&metadata->my_uuid, uuid, sizeof(struct nexus_uuid));

    *decrypted_metadata_contents = decrypted_buffer;

    ret = 0;
out:
    if (ret) {
        if (decrypted_buffer) {
            free(decrypted_buffer);
        }

        if (metadata) {
            free(metadata);
        }

        return NULL;
    }

    if (raw_buffer_ext) {
        if (raw_buffer_ext->buffer) {
            ocall_free(raw_buffer_ext->buffer);
        }

        ocall_free(raw_buffer_ext);
    }

    return metadata;
}

int
metadata_write(struct metadata * metadata,
               void            * metadata_object,
               size_t            buflen,
               crypto_mac_t    * mac)
{
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
