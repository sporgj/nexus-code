#include "internal.h"
#include <time.h>
#include <nexus_datastore.h>


static struct metadata_buf *
__alloc_metadata_buf(struct nexus_uuid * uuid)
{
    struct metadata_buf * buf = nexus_malloc(sizeof(struct metadata_buf));

    nexus_uuid_copy(uuid, &buf->uuid);

    return buf;
}

static void
__update_metadata_buf(struct metadata_buf * buf, uint8_t * ptr, size_t size, bool copy)
{
    if (buf->addr) {
        nexus_free(buf->addr);
    }

    if (copy) {
        buf->addr = nexus_malloc(size);
        memcpy(buf->addr, ptr, size);
    } else {
        buf->addr = ptr;
    }

    buf->size = size;

    // the last time we "synced" buffer
    buf->timestamp = time(NULL);
}

uint8_t *
io_buffer_get(struct nexus_uuid   * uuid,
              nexus_io_flags_t      flags,
              size_t              * p_size,
              size_t              * p_timestamp,
              struct nexus_volume * volume)
{
    struct sgx_backend       * sgx_backend  = (struct sgx_backend *)volume->private_data;

    struct metadata_buf      * metadata_buf = NULL;

    struct nexus_file_handle * locked_file  = NULL;

    bool                       is_new       = false;

    struct nexus_stat          stat;


    // first check the cached metadata buffer
    metadata_buf = buffer_manager_find(sgx_backend->buf_manager, uuid);

    if (metadata_buf == NULL) {
        // if none, create an empty entry and go read contents from disk
        is_new       = true;

        metadata_buf = __alloc_metadata_buf(uuid);
        goto read_datastore;
    }

    if (nexus_datastore_stat_uuid(volume->metadata_store, uuid, NULL, &stat)) {
        log_error("could not stat metadata file\n");
        return NULL;
    }

    // if nothing changed and we are just reading, just return the buffer
    if (stat.timestamp <= metadata_buf->timestamp && !(flags & NEXUS_FWRITE)) {
        *p_timestamp = metadata_buf->timestamp;
        *p_size      = metadata_buf->size;

        return metadata_buf->addr;
    }

read_datastore:
    locked_file = nexus_datastore_fopen(volume->metadata_store, uuid, NULL, flags);

    if (locked_file == NULL) {
        log_error("nexus_datastore_fopen FAILED\n");
        return NULL;
    }

    if (flags & NEXUS_FREAD) {
        uint8_t * addr = NULL;

        if (nexus_datastore_fread(volume->metadata_store, locked_file, &addr, p_size)) {
            nexus_datastore_fclose(volume->metadata_store, locked_file);
            log_error("nexus_datastore_fread FAILED\n");
            return NULL;
        }

        __update_metadata_buf(metadata_buf, addr, *p_size, false);
    }

    // if open on write, keep the file handle
    if (flags & NEXUS_FWRITE) {
        metadata_buf->locked_file = locked_file;
    } else {
        // otherwise, we close the file
        nexus_datastore_fclose(volume->metadata_store, locked_file);
    }

    *p_timestamp = metadata_buf->timestamp;

    if (is_new) {
        buffer_manager_add(sgx_backend->buf_manager, metadata_buf);
    }

    return metadata_buf->addr;
}

int
io_buffer_put(struct nexus_uuid * uuid, size_t * timestamp, struct nexus_volume * volume)
{
    struct sgx_backend  * sgx_backend  = (struct sgx_backend *)volume->private_data;

    struct metadata_buf * metadata_buf = buffer_manager_find(sgx_backend->buf_manager, uuid);

    int ret = -1;


    if (metadata_buf == NULL || metadata_buf->locked_file == NULL) {
        log_error("no locked file on metadata\n");
        return -1;
    }

    ret = nexus_datastore_fwrite(volume->metadata_store,
                                 metadata_buf->locked_file,
                                 metadata_buf->addr,
                                 metadata_buf->size);

    if (ret != 0) {
        nexus_datastore_fclose(volume->metadata_store, metadata_buf->locked_file);
        metadata_buf->locked_file = NULL;

        log_error("could not write metadata file\n");
        return -1;
    }

    nexus_datastore_fclose(volume->metadata_store, metadata_buf->locked_file);

    metadata_buf->locked_file = NULL;

    metadata_buf->timestamp = time(NULL);

    *timestamp = metadata_buf->timestamp;

    return 0;
}

int
io_buffer_flush(struct nexus_uuid   * uuid,
                uint8_t             * buffer,
                size_t                size,
                size_t              * timestamp,
                struct nexus_volume * volume)
{
    struct sgx_backend  * sgx_backend  = (struct sgx_backend *)volume->private_data;

    struct metadata_buf * metadata_buf = buffer_manager_find(sgx_backend->buf_manager, uuid);

    int ret = -1;


    if (metadata_buf == NULL || metadata_buf->locked_file == NULL) {
        log_error("no locked file on metadata\n");
        return -1;
    }

    ret = nexus_datastore_fwrite(volume->metadata_store,
                                 metadata_buf->locked_file,
                                 buffer,
                                 size);

    if (ret != 0) {
        nexus_datastore_fclose(volume->metadata_store, metadata_buf->locked_file);
        metadata_buf->locked_file = NULL;

        log_error("could not write metadata file\n");
        return -1;
    }

    nexus_datastore_fclose(volume->metadata_store, metadata_buf->locked_file);

    __update_metadata_buf(metadata_buf, buffer, size, true);

    metadata_buf->locked_file = NULL;

    *timestamp = metadata_buf->timestamp;

    return 0;
}

struct metadata_buf *
io_buffer_lock(struct nexus_uuid * uuid, struct nexus_volume * volume)
{
    struct sgx_backend  * sgx_backend  = (struct sgx_backend *)volume->private_data;

    struct metadata_buf * metadata_buf = buffer_manager_find(sgx_backend->buf_manager, uuid);

    if (metadata_buf == NULL) {
        metadata_buf = __alloc_metadata_buf(uuid);
        buffer_manager_add(sgx_backend->buf_manager, metadata_buf);
    }


    if (metadata_buf->locked_file == NULL) {
        metadata_buf->locked_file = nexus_datastore_fopen(volume->metadata_store,
                                                          uuid,
                                                          NULL,
                                                          NEXUS_FWRITE);

        if (metadata_buf->locked_file == NULL) {
            log_error("nexus_datastore_fopen FAILED\n");
            return NULL;
        }
    }

    return metadata_buf;
}

uint8_t *
io_buffer_alloc(struct nexus_uuid * uuid, size_t size, struct nexus_volume * volume)
{
    uint8_t             * addr         = NULL;

    struct metadata_buf * metadata_buf = io_buffer_lock(uuid, volume);

    if (metadata_buf == NULL) {
        log_error("could not lock metadata\n");
        return NULL;
    }

    addr = nexus_malloc(size);

    __update_metadata_buf(metadata_buf, addr, size, false);

    metadata_buf->timestamp = 0;

    return addr;
}
