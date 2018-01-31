#include "enclave_internal.h"

struct nexus_raw_buf {
    struct nexus_uuid uuid;

    size_t buffer_size;

    uint8_t * external_addr;

    uint8_t * internal_addr;
};


struct nexus_raw_buf *
nexus_raw_buf_create(struct nexus_uuid * uuid)
{
    struct nexus_raw_buf * raw_buf = NULL;

    void * external_addr = NULL;
    size_t external_size = 0;

    external_addr = buffer_layer_get(uuid, &external_size);
    if (external_addr == NULL) {
        log_error("could not retrieve external address\n");
        return NULL;
    }

    raw_buf = nexus_malloc(sizeof(struct nexus_raw_buf));


    raw_buf->external_addr = external_addr;
    raw_buf->buffer_size   = external_size;

    nexus_uuid_copy(uuid, &raw_buf->uuid);

    return raw_buf;
}

struct nexus_raw_buf *
nexus_raw_buf_new(size_t size)
{
    struct nexus_raw_buf * raw_buf = NULL;

    raw_buf = nexus_malloc(sizeof(struct nexus_raw_buf));

    raw_buf->buffer_size   = size;
    raw_buf->internal_addr = nexus_malloc(size);

    return raw_buf;
}

void
nexus_raw_buf_free(struct nexus_raw_buf * raw_buf)
{
    if (raw_buf->external_addr) {
        buffer_layer_put(&raw_buf->uuid);
    }

    if (raw_buf->internal_addr) {
        nexus_free(raw_buf->internal_addr);
    }

    nexus_free(raw_buf);
}

uint8_t *
nexus_raw_buf_get(struct nexus_raw_buf * raw_buf, size_t * buffer_size)
{
    if (raw_buf->internal_addr != NULL) {
        return raw_buf->internal_addr;
    }

    if (raw_buf->external_addr == NULL) {
        log_error("raw buffer external_addr is NULL");
        return NULL;
    }

    raw_buf->internal_addr = nexus_malloc(raw_buf->buffer_size);

    memcpy(raw_buf->internal_addr, raw_buf->external_addr, raw_buf->buffer_size);

    *buffer_size = raw_buf->buffer_size;

    return raw_buf->internal_addr;
}

int
nexus_raw_buf_put(struct nexus_raw_buf * raw_buf)
{
    if (raw_buf->external_addr == NULL) {
        raw_buf->external_addr = buffer_layer_alloc(raw_buf->buffer_size, &raw_buf->uuid);

        if (raw_buf->external_addr == NULL) {
            log_error("buffer_layer_alloc FAILED\n");
            return -1;
        }
    }

    memcpy(raw_buf->external_addr, raw_buf->internal_addr, raw_buf->buffer_size);

    return 0;
}
