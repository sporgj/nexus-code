static uint8_t *
__read_from_disk(struct nexus_datastore * datastore,
                 struct nexus_uuid      * uuid,
                 nexus_io_mode_t          mode,
                 size_t                 * p_size)
{
    struct nexus_file_handle * file_handle = NULL;

    uint8_t * addr = NULL;

    int ret = -1;


    file_handle = nexus_datastore_fopen(datastore, uuid, NULL, mode);

    if (file_handle == NULL) {
        log_error("could not open locked file\n");
        return NULL;
    }

    ret = nexus_datastore_fread(datastore, file_handle, &addr, p_size);

    if (ret != 0) {
        log_error("nexus_datastore_fread_uuid FAILED\n");
        goto out_err;
    }

    // add it to the lock manager
    if (mode & NEXUS_FWRITE) {
        ret = lock_manager_add(sgx_backend->lock_manager, uuid, file_handle));

        if (ret != 0) {
            log_error("could not store locked file\n");
            goto out_err;
        }
    } else {
        nexus_datastore_fclose(uuid, file_handle);
    }

    return addr;

out_err:
    nexus_datastore_fclose(datastore, file_handle);

    if (addr) {
        free(addr);
    }

    return NULL;
}

uint8_t *
io_buffer_get(struct nexus_uuid   * uuid,
              nexus_io_mode_t       mode,
              size_t              * p_size,
              struct nexus_volume * volume)
{
    struct sgx_backend * sgx_backend = (struct sgx_backend *)volume->private_data;

    uint8_t            * addr        = NULL;

    struct __buf       * buf         = NULL;

    struct nexus_stat    stat;

    int                  ret         = -1;


    buf = buffer_manager_get(sgx_backend->buf_manager, uuid);

    if (buf == NULL) {
        goto read_datastore;
    }

    ret = nexus_datastore_stat_uuid(volume->metadata_store, uuid, &stat);

    if (ret != 0) {
        log_error("could not stat metadata file\n");
        goto out_err;
    }

    // if nothing changed, just return the buffer
    if (stat.timestamp <= buf->timestamp) {
        *p_size = buf->size;
        return buf->addr;
    }

read_datastore:
    addr = __read_from_disk(volume, uuid, mode, p_size);

    if (addr == NULL) {
        log_error("reading from disk FAILED\n");
        goto out_err;
    }

    if (buffer_manager_add(sgx_backend->buf_manager, addr, size, uuid)) {
        nexus_free(addr);

        log_error("buffer_manager_add FAILED\n");
        goto out_err;
    }

    return addr;

out_err:
    if (buf) {
        __buffer_manager_put(sgx_backend->buf_manager, buf);
    }

    return NULL;
}

int
__flush_metadata(struct lock_manager    * lock_manager,
                 struct nexus_datastore * datastore,
                 struct __buf           * buf)
{
    struct nexus_file_handle * file_handle = lock_manager_del(sgx_backend->lock_manager, uuid);

    if (file_handle) {
        ret = nexus_datastore_fwrite(datastore, file_handle, buf->addr, buf->size);

        nexus_datastore_fclose(datastore, file_handle);

        if (ret != 0) {
            log_error("could not write data file\n");
            return -1;
        }
    }

    return 0;
}

int
io_buffer_put(struct nexus_uuid * uuid, struct nexus_volume * volume)
{
    struct sgx_backend * sgx_backend = (struct sgx_backend *)volume->private_data;

    struct __buf       * buf         = NULL;

    int                  ret         = 0;

    // the caller already got a ref count to buffer
    buf = buffer_manager_find(sgx_backend->buf_manager, uuid);

    if (buf == NULL) {
        log_error("buffer_manager_get returned NULL\n");
        return -1;
    }

    ret = __flush_metadata(sgx_backend->lock_manager, volume->metadata_store, buf);

    buffer_manager_put(sgx_backend->buf_manager, buf);

    return ret;
}

uint8_t *
io_buffer_alloc(size_t size, struct nexus_uuid * uuid, struct nexus_volume * volume)
{
    struct sgx_backend       * sgx_backend = (struct sgx_backend *)volume->private_data;

    // check if the lock manager already has a locked file
    locked_item = __lock_manager_get(sgx_backend->lock_manager, uuid);

    if (lock_manager_find(sgx_backend->lock_manager) == NULL) {
        struct nexus_file_handle * file_handle = NULL;

        file_handle = nexus_datastore_fopen(volume->metadata_store, uuid, NULL, NEXUS_FWRITE);

        if (file_handle == NULL) {
            log_error("could not open metadata file\n");
            return NULL;
        }

        if (lock_manager_add(sgx_backend->lock_manager, uuid, file_handle)) {
            nexus_datastore_fclose(volume->metadata_store, file_handle);

            log_error("could not add file to lock manager\n");
            return NULL;
        }
    }

    return buffer_manager_alloc(sgx_backend->buf_manager, uuid, size);
out_err:
    return NULL;
}
