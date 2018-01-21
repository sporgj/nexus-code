#include "internal.h"

void *
buffer_layer_alloc(size_t total_size, struct nexus_uuid * uuid)
{
    uint8_t * external_addr = NULL;

    int err = -1;


    if (uuid == NULL) {
        log_error("uuid argument null\n");
        return NULL;
    }

    err = ocall_buffer_alloc(&external_addr, total_size, uuid);
    if (err) {
        log_error("could not allocate space for crypto_buffer\n");
        return NULL;
    }

    return external_addr;
}

void *
buffer_layer_get(struct nexus_uuid * uuid, size_t * size)
{
    uint8_t * external_addr = NULL;

    int err = -1;


    err = ocall_buffer_get(&external_addr, uuid, size);

    if (err || external_addr == NULL) {
        log_error("ocall_buffer_get FAILED\n");
        return NULL;
    }

    return external_addr;
}

int
buffer_layer_put(struct nexus_uuid * buffer_uuid)
{
    // XXX for now, the put just frees the external buffer
    ocall_buffer_free(buffer_uuid);

    return 0;
}
