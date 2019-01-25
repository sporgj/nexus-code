#include "internal.h"
#include <time.h>
#include <nexus_datastore.h>
#include <nexus_file_handle.h>


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

static inline uint8_t *
__io_buffer_get(struct nexus_uuid   * uuid,
                nexus_io_flags_t      flags,
                size_t              * p_size,
                size_t              * p_timestamp,
                struct nexus_volume * volume)
{
    struct sgx_backend       * sgx_backend  = (struct sgx_backend *)volume->private_data;

    struct metadata_buf      * metadata_buf = NULL;

    struct nexus_file_handle * locked_file  = NULL;

    bool                       is_new       = false;

    struct stat stat_buf;


    // first check the cached metadata buffer
    metadata_buf = buffer_manager_find(sgx_backend->buf_manager, uuid);

    if (metadata_buf == NULL) {
        // if none, create an empty entry and go read contents from disk
        is_new       = true;

        metadata_buf = __alloc_metadata_buf(uuid);
        goto read_datastore;
    }

    if (nexus_datastore_stat_uuid(volume->metadata_store, uuid, NULL, &stat_buf)) {
        log_error("could not stat metadata file\n");
        return NULL;
    }

    // if nothing changed and we are just reading, just return the buffer
    if (stat_buf.st_mtime <= (int)metadata_buf->timestamp && !(flags & NEXUS_FWRITE)) {
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

uint8_t *
io_buffer_get(struct nexus_uuid   * uuid,
              nexus_io_flags_t      flags,
              size_t              * p_size,
              size_t              * p_timestamp,
              struct nexus_volume * volume)
{
    uint8_t * result = NULL;

    BACKEND_SGX_IOBUF_START(IOBUF_GET);

    result = __io_buffer_get(uuid, flags, p_size, p_timestamp, volume);

    BACKEND_SGX_IOBUF_FINISH(IOBUF_GET);

    return result;
}

static int
__io_buffer_put(struct nexus_uuid   * uuid,
                uint8_t             * buffer,
                size_t                size,
                size_t              * timestamp,
                struct nexus_volume * volume)
{
    struct sgx_backend  * sgx_backend  = (struct sgx_backend *)volume->private_data;

    struct metadata_buf * metadata_buf = NULL;


    metadata_buf = buffer_manager_find(sgx_backend->buf_manager, uuid);

    if (metadata_buf == NULL || metadata_buf->locked_file == NULL) {
        log_error("no locked file on metadata\n");
        return -1;
    }

    if (nexus_datastore_fwrite(volume->metadata_store, metadata_buf->locked_file, buffer, size)) {
        log_error("could not write metadata file\n");
        goto out_err;
    }

    if (nexus_datastore_fflush(volume->metadata_store, metadata_buf->locked_file)) {
        log_error("nexus_datastore_fflush() FAILED\n");
        goto out_err;
    }

    nexus_datastore_fclose(volume->metadata_store, metadata_buf->locked_file);

    __update_metadata_buf(metadata_buf, buffer, size, true);

    metadata_buf->locked_file = NULL;

    *timestamp = metadata_buf->timestamp;

    return 0;

out_err:
    nexus_datastore_fclose(volume->metadata_store, metadata_buf->locked_file);
    metadata_buf->locked_file = NULL;

    return -1;
}

int
io_buffer_put(struct nexus_uuid   * uuid,
              uint8_t             * buffer,
              size_t                size,
              size_t              * timestamp,
              struct nexus_volume * volume)
{
    BACKEND_SGX_IOBUF_START(IOBUF_PUT);

    int ret = __io_buffer_put(uuid, buffer, size, timestamp, volume);

    BACKEND_SGX_IOBUF_FINISH(IOBUF_PUT);

    return ret;
}

static inline struct metadata_buf *
__io_buffer_lock(struct nexus_uuid * uuid, nexus_io_flags_t flags, struct nexus_volume * volume)
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
                                                          flags);

        if (metadata_buf->locked_file == NULL) {
            log_error("nexus_datastore_fopen FAILED\n");
            return NULL;
        }
    }

    return metadata_buf;
}

struct metadata_buf *
io_buffer_lock(struct nexus_uuid * uuid, nexus_io_flags_t flags, struct nexus_volume * volume)
{
    struct metadata_buf * result = NULL;

    BACKEND_SGX_IOBUF_START(IOBUF_LOCK);

    result = __io_buffer_lock(uuid, flags, volume);

    BACKEND_SGX_IOBUF_FINISH(IOBUF_LOCK);

    return result;
}


static inline struct metadata_buf *
__io_buffer_unlock(struct nexus_uuid * uuid, struct nexus_volume * volume)
{
    struct sgx_backend  * sgx_backend  = (struct sgx_backend *)volume->private_data;

    struct metadata_buf * metadata_buf = buffer_manager_find(sgx_backend->buf_manager, uuid);

    if (metadata_buf && metadata_buf->locked_file) {
        nexus_datastore_fclose(volume->metadata_store, metadata_buf->locked_file);

        return metadata_buf;
    }

    return NULL;
}

struct metadata_buf *
io_buffer_unlock(struct nexus_uuid * uuid, struct nexus_volume * volume)
{
    struct metadata_buf * result = NULL;

    BACKEND_SGX_IOBUF_START(IOBUF_UNLOCK);

    result = __io_buffer_unlock(uuid, volume);

    BACKEND_SGX_IOBUF_FINISH(IOBUF_UNLOCK);

    return result;
}

int
io_buffer_new(struct nexus_uuid * metadata_uuid, struct nexus_volume * volume)
{
    int result = -1;

    BACKEND_SGX_IOBUF_START(IOBUF_NEW);

    result = nexus_datastore_new_uuid(volume->metadata_store, metadata_uuid, NULL);

    BACKEND_SGX_IOBUF_FINISH(IOBUF_NEW);

    return result;
}

int
io_buffer_del(struct nexus_uuid * metadata_uuid, struct nexus_volume * volume)
{
    struct sgx_backend * sgx_backend = (struct sgx_backend *)volume->private_data;

    int result = -1;


    buffer_manager_del(sgx_backend->buf_manager, metadata_uuid);

    BACKEND_SGX_IOBUF_START(IOBUF_DEL);

    result = nexus_datastore_del_uuid(volume->metadata_store, metadata_uuid, NULL);

    BACKEND_SGX_IOBUF_FINISH(IOBUF_DEL);

    return result;
}

int
io_buffer_stattime(struct nexus_uuid * uuid, size_t * timestamp, struct nexus_volume * volume)
{
    struct stat stat_buf;

    int result = -1;

    BACKEND_SGX_IOBUF_START(IOBUF_STAT);

    result = nexus_datastore_stat_uuid(volume->metadata_store, uuid, NULL, &stat_buf);

    BACKEND_SGX_IOBUF_FINISH(IOBUF_STAT);

    if (result) {
        log_error("could not stat metadata file\n");
        return -1;
    }


    *timestamp = stat_buf.st_mtime;

    return 0;
}
