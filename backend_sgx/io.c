#include "internal.h"
#include <time.h>
#include <nexus_datastore.h>

static uint8_t *
__read_from_disk(struct nexus_datastore    * datastore,
                 struct nexus_uuid         * uuid,
                 nexus_io_flags_t            flags,
                 size_t                    * p_size,
                 struct nexus_file_handle ** locked_file)
{
    struct nexus_file_handle * file_handle = NULL;

    uint8_t                  * addr        = NULL;


    file_handle = nexus_datastore_fopen(datastore, uuid, NULL, flags);

    if (file_handle == NULL) {
        log_error("could not open locked file\n");
        return NULL;
    }


    if (nexus_datastore_fread(datastore, file_handle, &addr, p_size)) {
        nexus_datastore_fclose(datastore, file_handle);

        log_error("nexus_datastore_fread_uuid FAILED\n");
        return NULL;
    }


    if (flags & NEXUS_FWRITE) {
        *locked_file = file_handle;
    } else {
        nexus_datastore_fclose(datastore, file_handle);
        *locked_file = NULL;
    }

    return addr;
}

uint8_t *
io_buffer_get(struct nexus_uuid   * uuid,
              nexus_io_flags_t      flags,
              size_t              * p_size,
              size_t              * p_timestamp,
              struct nexus_volume * volume)
{
    struct sgx_backend       * sgx_backend = (struct sgx_backend *)volume->private_data;

    uint8_t                  * addr        = NULL;

    struct metadata_buf      * buf         = NULL;

    struct nexus_file_handle * locked_file = NULL;

    struct nexus_stat          stat;


    buf = buffer_manager_get(sgx_backend->buf_manager, uuid);

    if (buf == NULL) {
        goto read_datastore;
    }

    if (nexus_datastore_stat_uuid(volume->metadata_store, uuid, NULL, &stat)) {
        log_error("could not stat metadata file\n");
        goto out_err;
    }

    // if nothing changed, just return the buffer
    if (stat.timestamp <= buf->timestamp) {
        *p_timestamp = buf->timestamp;
        *p_size      = buf->size;

        return buf->addr;
    }

read_datastore:
    addr = __read_from_disk(volume->metadata_store, uuid, flags, p_size, &locked_file);

    if (addr == NULL) {
        log_error("reading from disk FAILED\n");
        goto out_err;
    }

    buf = __buffer_manager_add(sgx_backend->buf_manager, addr, *p_size, uuid);

    if (buf == NULL) {
        nexus_free(addr);
        buf = NULL;

        log_error("__buffer_manager_add FAILED\n");
        goto out_err;
    }

    buf->locked_file = locked_file;

    *p_timestamp = buf->timestamp;

    return addr;

out_err:
    if (buf) {
        buffer_manager_put(sgx_backend->buf_manager, &buf->uuid);
    }

    return NULL;
}

int
__flush_metadata(struct nexus_datastore * datastore, struct metadata_buf * buf)
{
    if (buf->locked_file) {
        int ret = nexus_datastore_fwrite(datastore, buf->locked_file, buf->addr, buf->size);

        nexus_datastore_fclose(datastore, buf->locked_file);

        buf->locked_file = NULL;

        if (ret != 0) {
            log_error("could not write data file\n");
            return -1;
        }

        // the last time we "synced" buffer
        buf->timestamp = time(NULL);
    }

    return 0;
}

int
io_buffer_put(struct nexus_uuid * uuid, size_t * timestamp, struct nexus_volume * volume)
{
    struct sgx_backend  * sgx_backend = (struct sgx_backend *)volume->private_data;

    struct metadata_buf * buf         = NULL;

    int                   ret         = 0;

    // the caller already got a ref count to buffer
    buf = buffer_manager_find(sgx_backend->buf_manager, uuid);

    if (buf == NULL) {
        log_error("buffer_manager_get returned NULL\n");
        return -1;
    }

    ret = __flush_metadata(volume->metadata_store, buf);

    buffer_manager_put(sgx_backend->buf_manager, &buf->uuid);

    *timestamp = buf->timestamp;

    return ret;
}

uint8_t *
io_buffer_alloc(size_t size, struct nexus_uuid * uuid, struct nexus_volume * volume)
{
    struct sgx_backend * sgx_backend = (struct sgx_backend *)volume->private_data;

    struct metadata_buf * buf = __buffer_manager_alloc(sgx_backend->buf_manager, size, uuid);

    if (buf == NULL) {
        log_error("could not allocate buffer\n");
        return NULL;
    }

    if (buf->locked_file == NULL) {
        buf->locked_file = nexus_datastore_fopen(volume->metadata_store, uuid, NULL, NEXUS_FWRITE);

        if (buf->locked_file == NULL) {
            buffer_manager_del(sgx_backend->buf_manager, &buf->uuid);

            log_error("could not open metadata file\n");
            return NULL;
        }
    }

    return buf->addr;
}
