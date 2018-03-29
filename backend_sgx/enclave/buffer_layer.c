#include "enclave_internal.h"

void *
buffer_layer_alloc(size_t total_size, struct nexus_uuid * uuid)
{
    uint8_t * external_addr = NULL;

    int err = -1;


    if (uuid == NULL) {
        log_error("uuid argument null\n");
        return NULL;
    }

    err = ocall_buffer_alloc(&external_addr, total_size, uuid, global_volume);
    if (err || external_addr == NULL) {
        log_error("could not allocate space for crypto_buffer (err=%d)\n", err);
        return NULL;
    }

    return external_addr;
}

void *
buffer_layer_get(struct nexus_uuid * uuid, size_t * size)
{
    uint8_t * external_addr = NULL;

    int err = -1;


    err = ocall_buffer_get(&external_addr, uuid, size, global_volume);

    if (err || external_addr == NULL) {
        log_error("ocall_buffer_get FAILED (err=%d)\n", err);
        return NULL;
    }

    return external_addr;
}

int
buffer_layer_put(struct nexus_uuid * buffer_uuid)
{
    ocall_buffer_put(buffer_uuid, global_volume);

    return 0;
}

void
buffer_layer_delete(struct nexus_uuid * uuid)
{
    int err = -1;
    int ret = -1;

    err = ocall_buffer_del(&ret, uuid, global_volume);

    // XXX: what do to about err?
    (void) err;
    (void) ret;
}

int
buffer_layer_copy(struct nexus_uuid * from_uuid, struct nexus_uuid * to_uuid)
{
    // get a reference and copy the uuid
    void * buffer = NULL;
    size_t buflen = 0;

    buffer = buffer_layer_get(from_uuid, &buflen);

    if (buffer == NULL) {
        log_error("could not acquire reference to buffer\n");
        return -1;
    }

    nexus_uuid_copy(from_uuid, to_uuid);

    return 0;
}

int
buffer_layer_flush(struct nexus_uuid * uuid)
{
    int err = -1;
    int ret = -1;

    err = ocall_buffer_flush(&ret, uuid, global_volume);

    if (err || ret) {
        log_error("ocall_buffer_flush FAILED (err=%d, ret=%d)\n", err, ret);
        return -1;
    }

    return 0;
}

int
buffer_layer_hardlink(struct nexus_uuid * link_uuid, struct nexus_uuid * target_uuid)
{
    int err = -1;
    int ret = -1;

    err = ocall_buffer_hardlink(&ret, link_uuid, target_uuid, global_volume);

    if (err || ret) {
        log_error("ocall_buffer_hardlink FAILED (err=%d, ret=%d)\n", err, ret);
        return -1;
    }

    return 0;
}

int
buffer_layer_rename(struct nexus_uuid * from_uuid, struct nexus_uuid * to_uuid)
{
    int err = -1;
    int ret = -1;

    err = ocall_buffer_rename(&ret, from_uuid, to_uuid, global_volume);

    if (err || ret) {
        log_error("ocall_buffer_hardlink FAILED (err=%d, ret=%d)\n", err, ret);
        return -1;
    }

    return 0;
}
