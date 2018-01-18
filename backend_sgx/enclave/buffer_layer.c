#include "internal.h"

struct nexus_uuid *
buffer_layer_alloc(size_t total_size, uint8_t ** p_untrusted_ptr)
{
    struct nexus_uuid * buffer_uuid      = NULL;

    uint8_t           * untrusted_addr   = NULL;

    int err = -1;


    // XXX: we should probably combine the two ocalls into 1 using a
    // custom data structure
    err = ocall_buffer_alloc(&buffer_uuid, total_size);

    if (err || buffer_uuid == NULL) {
        log_error("could not allocate space for crypto_buffer\n");
        return NULL;
    }

    // get the untrusted address
    err = ocall_buffer_get(&untrusted_addr, buffer_uuid);
    if (err || untrusted_addr == NULL) {
        log_error("could not get untrusted pointer from UUID");
        goto cleanup;
    }


    *p_untrusted_ptr = untrusted_addr;

    return buffer_uuid;
cleanup:
    buffer_layer_free(buffer_uuid);
    nexus_free(buffer_uuid);

    return NULL;
}

struct nexus_uuid *
buffer_layer_create(uint8_t * untrusted_addr, size_t size)
{
    struct nexus_uuid * buffer_uuid = NULL;

    int err = -1;


    err = ocall_buffer_create(&buffer_uuid, untrusted_addr, size);
    if (err || buffer_uuid == NULL) {
        log_error("ocall_buffer_create() FAILED\n");
        return NULL;
    }

    return buffer_uuid;
}

int
buffer_layer_free(struct nexus_uuid * buffer_uuid)
{
    ocall_buffer_free(buffer_uuid);

    return 0;
}
