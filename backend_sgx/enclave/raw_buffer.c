#include "enclave_internal.h"

struct nexus_raw_buf {
    size_t    buffer_size;

    uint8_t * internal_addr;
};


struct nexus_raw_buf *
nexus_raw_buf_create(uint8_t * external_addr, size_t external_size)
{
    struct nexus_raw_buf * raw_buf = nexus_malloc(sizeof(struct nexus_raw_buf));

    if (external_addr == NULL) {
        nexus_free(raw_buf);
        log_error("raw buffer external_addr is NULL\n");
        return NULL;
    }

    raw_buf->buffer_size   = external_size;

    raw_buf->internal_addr = nexus_malloc(raw_buf->buffer_size);

    memcpy(raw_buf->internal_addr, external_addr, raw_buf->buffer_size);

    return raw_buf;
}

void
nexus_raw_buf_free(struct nexus_raw_buf * raw_buf)
{
    if (raw_buf->internal_addr) {
        nexus_free(raw_buf->internal_addr);
    }

    nexus_free(raw_buf);
}

uint8_t *
nexus_raw_buf_get(struct nexus_raw_buf * raw_buf, size_t * buffer_size)
{
    if (raw_buf->internal_addr == NULL) {
        log_error("raw buffer internal_addr is NULL\n");
        return NULL;
    }

    *buffer_size = raw_buf->buffer_size;

    return raw_buf->internal_addr;
}
