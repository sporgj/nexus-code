#include "internal.h"
#include <time.h>
#include <nexus_datastore.h>
#include <nexus_file_handle.h>



static int
__parse_file_metadata(struct nexus_file_handle * file_handle, uint8_t ** p_buffer, size_t * p_buflen);

static int
__store_file_metadata(struct metadata_buf * metadata_buf,
                      size_t                filesize,
                      struct nexus_volume * volume);



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

static inline int
__read_metadata_file(struct nexus_file_handle  * file_handle,
                     struct nexus_volume       * volume,
                     nexus_io_flags_t            flags,
                     uint8_t                  ** addr,
                     size_t                    * p_size)
{
    if ((flags & NEXUS_IO_FNODE)) {
        if (__parse_file_metadata(file_handle, addr, p_size)) {
            nexus_datastore_fclose(volume->metadata_store, file_handle);
            log_error("__parse_file_metadata FAILED\n");
            return -1;
        }
    } else if (nexus_datastore_fread(volume->metadata_store, file_handle, addr, p_size)) {
        nexus_datastore_fclose(volume->metadata_store, file_handle);
        log_error("nexus_datastore_fread FAILED\n");
        return -1;
    }

    return 0;
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



    if (nexus_datastore_stat_uuid(volume->metadata_store, uuid, NULL, &stat_buf)) {
        log_error("could not stat metadata file\n");
        return NULL;
    }

    // first check the cached metadata buffer
    metadata_buf = buffer_manager_find(sgx_backend->buf_manager, uuid);

    if (metadata_buf == NULL) {
        // if none, create an empty entry and go read contents from disk
        is_new       = true;

        metadata_buf = __alloc_metadata_buf(uuid);
        goto read_datastore;
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

        if (stat_buf.st_size == 0) {
            addr = nexus_malloc(1);
            *p_size = 0;
        } else if (__read_metadata_file(locked_file, volume, flags, &addr, p_size)) {
            log_error("__read_metadata_file() FAILE\n");
            return NULL;
        }

        __update_metadata_buf(metadata_buf, addr, *p_size, false);
    }

    // if open on write, keep the file handle
    if ((flags & NEXUS_FWRITE) || ((flags & NEXUS_IO_FCRYPTO) && (flags & NEXUS_IO_FNODE))) {
        metadata_buf->locked_file_flags = flags;
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

    struct metadata_buf * metadata_buf = buffer_manager_find(sgx_backend->buf_manager, uuid);

    if (metadata_buf == NULL || metadata_buf->locked_file == NULL) {
        log_error("no locked file on metadata\n");
        return -1;
    }

    if (metadata_buf->locked_file_flags & NEXUS_IO_FCRYPTO) {
        // this will be saved in io_file_crypto_finish()
        __update_metadata_buf(metadata_buf, buffer, size, true);
        return 0;
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

    metadata_buf->locked_file_flags = flags;

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

        metadata_buf->locked_file = NULL;

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



struct nexus_file_crypto *
io_file_crypto_start(int                  trusted_xfer_id,
                     struct nexus_uuid  * uuid,
                     file_crypto_mode     mode,
                     size_t               filesize,
                     char               * filepath,
                     struct sgx_backend * sgx_backend)
{
    struct nexus_file_crypto * file_crypto = nexus_malloc(sizeof(struct nexus_file_crypto));


    file_crypto->metadata_buf = buffer_manager_find(sgx_backend->buf_manager, uuid);

    if (file_crypto->metadata_buf == NULL) {
        nexus_free(file_crypto);
        log_error("could not get metadata_buf\n");
        return NULL;
    }


    // if the locked file is empty, open in read mode.
    // this usually happens on decrypting a file (the enclave does not lock the file)
    if (file_crypto->metadata_buf->locked_file == NULL) {
        file_crypto->metadata_buf = __io_buffer_lock(uuid, NEXUS_FREAD, sgx_backend->volume);

        if (file_crypto->metadata_buf == NULL) {
            nexus_free(file_crypto);
            log_error("could not get metadata_buf\n");
            return NULL;
        }
    }

    file_crypto->mode            = mode;
    file_crypto->trusted_xfer_id = trusted_xfer_id;
    file_crypto->filesize        = filesize;
    file_crypto->filepath        = strndup(filepath, PATH_MAX);
    file_crypto->sgx_backend     = sgx_backend;

    return file_crypto;
}

int
io_file_crypto_seek(struct nexus_file_crypto * file_crypto, size_t offset)
{
    struct nexus_file_handle * file_handle = file_crypto->metadata_buf->locked_file;

    file_crypto->offset = offset;

    if (lseek(file_handle->fd, offset, SEEK_SET) == -1) {
        return -1;
    }

    return 0;
}


int
io_file_crypto_read(struct nexus_file_crypto * file_crypto, uint8_t * output_buffer, size_t nbytes)
{
    struct nexus_file_handle * file_handle = file_crypto->metadata_buf->locked_file;

    int bytes_read = read(file_handle->fd, output_buffer, nbytes);

    if (bytes_read != (int)nbytes) {
        log_error("reading file (%s) failed. tried=%zu, got=%d\n",
                  file_handle->filepath,
                  nbytes,
                  bytes_read);
        return -1;
    }

    file_crypto->offset += bytes_read;

    return 0;
}

int
io_file_crypto_write(struct nexus_file_crypto  * file_crypto,
                     const uint8_t             * input_buffer,
                     size_t                      nbytes)
{
    struct nexus_file_handle * file_handle = file_crypto->metadata_buf->locked_file;

    int bytes_written = write(file_handle->fd, (uint8_t *)input_buffer, nbytes);

    if (bytes_written != (int)nbytes) {
        log_error("reading file (%s) failed. tried=%zu, got=%d\n",
                  file_handle->filepath,
                  nbytes,
                  bytes_written);
        return -1;
    }

    file_crypto->offset += bytes_written;

    return 0;
}


static int
__parse_file_metadata(struct nexus_file_handle * file_handle, uint8_t ** p_buffer, size_t * p_buflen)
{
    struct __filenode_info filenode_info;

    uint8_t * buffer = NULL;

    int nbytes = -1;


    if (lseek(file_handle->fd, -1 * sizeof(struct __filenode_info), SEEK_END) == -1) {
        log_error("lseek (offset=%zu, SEEK_END) on file handle FAILED\n",
                  sizeof(struct __filenode_info));
        return -1;
    }

    nbytes = read(file_handle->fd, &filenode_info, sizeof(struct __filenode_info));

    if (nbytes != sizeof(struct __filenode_info)) {
        log_error("reading filenode info failed. tried=%zu, got=%d\n",
                  sizeof(struct __filenode_info),
                  nbytes);
        perror("error:");
        return -1;
    }


    // seek to the beginning of metadata content and read the buffer
    if (lseek(file_handle->fd, filenode_info.filesize, SEEK_SET) == -1) {
        log_error("lseek (offset=%zu, SEEK_SET) failed\n", (size_t)filenode_info.filesize);
        return -1;
    }

    buffer = nexus_malloc(filenode_info.metadata_size);

    nbytes = read(file_handle->fd, buffer, filenode_info.metadata_size);

    if (nbytes != (int)filenode_info.metadata_size) {
        nexus_free(buffer);
        log_error("read failed. tried=%zu, got=%d\n", (size_t)filenode_info.metadata_size, nbytes);
        return -1;
    }

    *p_buflen = filenode_info.metadata_size;
    *p_buffer = buffer;

    return 0;
}


// the file_handle's position must be at the end of the data portion
static int
__store_file_metadata(struct metadata_buf * metadata_buf,
                      size_t                filesize,
                      struct nexus_volume * volume)
{
    struct nexus_file_handle * file_handle = metadata_buf->locked_file;

    struct __filenode_info  filenode_info;

    int nbytes = -1;


    nbytes = write(file_handle->fd, metadata_buf->addr, metadata_buf->size);

    if (nbytes != (int)metadata_buf->size) {
        log_error("could not write metadata content on file_crypto. tried=%zu, got=%d\n",
                  metadata_buf->size,
                  nbytes);
        return -1;
    }


    // write the footer
    filenode_info.metadata_size = metadata_buf->size;
    filenode_info.filesize      = filesize;

    nbytes = write(file_handle->fd, &filenode_info, sizeof(struct __filenode_info));

    if (nbytes != (int)sizeof(struct __filenode_info)) {
        log_error("could not write metadata content on file_crypto. tried=%zu, got=%d\n",
                  sizeof(struct __filenode_info),
                  nbytes);
        return -1;
    }

    if (nexus_datastore_fflush(volume->metadata_store, metadata_buf->locked_file)) {
        log_error("nexus_datastore_fflush() FAILED\n");
        return -1;
    }

    return 0;
}

int
io_file_crypto_finish(struct nexus_file_crypto * file_crypto)
{
    struct nexus_file_handle  * file_handle = file_crypto->metadata_buf->locked_file;

    struct nexus_volume * volume = file_crypto->sgx_backend->volume;

    size_t total_size = 0;

    int ret = -1;


    if (file_crypto->mode == FILE_ENCRYPT) {
        total_size = file_crypto->filesize + file_crypto->metadata_buf->size + sizeof(struct __filenode_info);

        // seek to the end of the data portion (the filesize)
        if (file_crypto->offset != file_crypto->filesize) {
            if (ftruncate(file_handle->fd, total_size)) {
                log_error("ftruncate FAILED (%s)\n", file_handle->filepath);
                goto out;
            }

            if (lseek(file_handle->fd, file_crypto->filesize, SEEK_SET) == -1) {
                log_error("lseek on file handle FAILED\n");
                goto out;
            }
        }

        if (__store_file_metadata(file_crypto->metadata_buf, file_crypto->filesize, volume)) {
            log_error("__store_file_crypto() FAILED\n");
            goto out;
        }
    }


    ret = 0;
out:
    nexus_datastore_fclose(volume->metadata_store, file_crypto->metadata_buf->locked_file);

    file_crypto->metadata_buf->locked_file = NULL;

    nexus_free(file_crypto->filepath);
    nexus_free(file_crypto);

    return ret;
}


int
io_buffer_truncate(struct nexus_uuid * uuid, size_t filesize, struct sgx_backend * sgx_backend)
{
    struct metadata_buf * metadata_buf = buffer_manager_find(sgx_backend->buf_manager, uuid);

    struct nexus_file_handle * file_handle = NULL;

    size_t total_size = 0;


    if (metadata_buf == NULL) {
        log_error("buffer_manager_find() FAILED\n");
        return -1;
    }

    if (metadata_buf->locked_file == NULL) {
        log_error("metadata_buffer has no locked_file\n");
        return -1;
    }


    file_handle = metadata_buf->locked_file;

    total_size = filesize + metadata_buf->size + sizeof(struct __filenode_info);

    if (ftruncate(file_handle->fd, total_size)) {
        log_error("ftruncate FAILED (%s)\n", file_handle->filepath);
        goto out_err;
    }

    if (lseek(file_handle->fd, filesize, SEEK_SET) == -1) {
        log_error("lseek on file handle FAILED\n");
        goto out_err;
    }

    if (__store_file_metadata(metadata_buf, filesize, sgx_backend->volume)) {
        log_error("__store_file_metadata() FAILED\n");
        goto out_err;
    }

    nexus_datastore_fclose(sgx_backend->volume->metadata_store, file_handle);

    return 0;

out_err:
    nexus_datastore_fclose(sgx_backend->volume->metadata_store, file_handle);

    return -1;
}
