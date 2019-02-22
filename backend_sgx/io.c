#include <pthread.h>
#include <time.h>

#include <nexus_datastore.h>
#include <nexus_file_handle.h>
#include <nexus_hashtable.h>

#include "internal.h"

struct __filenode_info {
    uint32_t    metadata_size;
    uint32_t    filedata_size;
} __attribute__((packed));



static int
__flush_metadata_file(struct metadata_buf * metadata_buf);

static inline size_t
__filenode_total_size(size_t filesize, struct metadata_buf * metadata_buf)
{
    return filesize + metadata_buf->size + sizeof(struct __filenode_info);
}


// reads the filenode metadata from the provided file handle
static int
__parse_filenode(struct nexus_file_handle * file_handle, uint8_t ** p_buffer, size_t * p_buflen)
{
    struct __filenode_info filenode_info;

    uint8_t * buffer = NULL;

    int nbytes = -1;


    // seek to the end and read the filenode info
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
        return -1;
    }


    // seek to the beginning of metadata content and read the buffer
    if (lseek(file_handle->fd, filenode_info.filedata_size, SEEK_SET) == -1) {
        log_error("lseek (offset=%zu, SEEK_SET) failed\n", (size_t)filenode_info.filedata_size);
        return -1;
    }

    buffer = nexus_malloc(filenode_info.metadata_size);

    nbytes = read(file_handle->fd, buffer, filenode_info.metadata_size);

    if (nbytes != (int)filenode_info.metadata_size) {
        nexus_free(buffer);
        log_error("reading filenode (%s) failed. tried=%zu, got=%d\n",
                  file_handle->filepath,
                  (size_t)filenode_info.metadata_size,
                  nbytes);
        return -1;
    }

    *p_buflen = filenode_info.metadata_size;
    *p_buffer = buffer;

    return 0;
}


static struct metadata_buf *
__alloc_metadata_buf(struct nexus_uuid * uuid, struct sgx_backend * sgx_backend)
{
    struct metadata_buf * buf = nexus_malloc(sizeof(struct metadata_buf));

    nexus_uuid_copy(uuid, &buf->uuid);

    buf->backend = sgx_backend;

    pthread_mutex_init(&buf->file_mutex, NULL);

    return buf;
}

void
__free_metadata_buf(struct metadata_buf * metadata_buf)
{
    if (metadata_buf->addr) {
        nexus_free(metadata_buf->addr);
    }

    nexus_free(metadata_buf);
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


static struct nexus_file_handle *
__metadata_buf_get_handle(struct metadata_buf * metadata_buf)
{
    return metadata_buf->file_handle;
}

/**
 * Returns a reference to the metadata buffer
 * @return metadata_buf->file_handle
 */
static struct nexus_file_handle *
__acquire_metadata_buf(struct metadata_buf * metadata_buf)
{
    struct nexus_file_handle * file_handle = __metadata_buf_get_handle(metadata_buf);

    if (file_handle == NULL) {
        return NULL;
    }

    if (nexus_io_in_lock_mode(metadata_buf->handle_flags)) {
        pthread_mutex_lock(&metadata_buf->file_mutex);
    }

    return file_handle;
}

/**
 * Returns the file handle unto the metadata_buf. Decrements the number of openers
 * @param metadata_buf
 */
static int
__release_metadata_buf(struct metadata_buf * metadata_buf)
{
    struct nexus_volume * volume = metadata_buf->backend->volume;

    nexus_io_flags_t flags;

    int ret = -1;

    if (metadata_buf->file_handle == NULL) {
        // XXX log a warning here
        return 0;
    }

    flags = metadata_buf->handle_flags;

    ret = nexus_datastore_fclose(volume->metadata_store, metadata_buf->file_handle);
    metadata_buf->file_handle  = NULL;
    metadata_buf->handle_flags = 0;

    if (ret != 0) {
        log_error("nexus_datastore_fclose() FAILED\n");
    }

    if (nexus_io_in_lock_mode(flags)) {
        pthread_mutex_unlock(&metadata_buf->file_mutex);
    }

    return ret;
}


static struct nexus_file_handle *
__open_metadata_file(struct metadata_buf * metadata_buf, nexus_io_flags_t flags)
{
    struct nexus_volume * volume = metadata_buf->backend->volume;

    struct nexus_datastore * datastore = volume->metadata_store;

    if (metadata_buf->file_handle) {
        if ((flags & metadata_buf->handle_flags) != flags) {
            log_error("metadata already has locked file with incompatible flags\n");
            return NULL;
        }

        return __acquire_metadata_buf(metadata_buf);
    }

    metadata_buf->file_handle = nexus_datastore_fopen(datastore, &metadata_buf->uuid, NULL, flags);

    if (metadata_buf->file_handle == NULL) {
        log_error("nexus_datastore_fopen FAILED\n");
        return NULL;
    }

    metadata_buf->handle_flags = flags;

    return __acquire_metadata_buf(metadata_buf);
}


static inline int
__read_metadata_file(struct metadata_buf * metadata_buf)
{
    struct nexus_file_handle * file_handle = metadata_buf->file_handle;
    struct nexus_volume      * volume      = metadata_buf->backend->volume;
    nexus_io_flags_t           flags       = metadata_buf->handle_flags;

    uint8_t * addr = NULL;
    size_t    size = 0;


    if ((flags & NEXUS_IO_FNODE)) {
        if (__parse_filenode(file_handle, &addr, &size)) {
            log_error("__parse_file_metadata FAILED\n");
            return -1;
        }

        __update_metadata_buf(metadata_buf, addr, size, false);

        return 0;
    }

    if (nexus_datastore_fread(volume->metadata_store, file_handle, &addr, &size)) {
        log_error("nexus_datastore_fread FAILED\n");
        return -1;
    }

    __update_metadata_buf(metadata_buf, addr, size, false);

    return 0;
}

static inline int
__write_metadata_file(struct metadata_buf * metadata_buf, uint8_t * buffer, size_t size)
{
    struct nexus_file_handle * file_handle = __metadata_buf_get_handle(metadata_buf);

    struct nexus_volume * volume = metadata_buf->backend->volume;

    if (nexus_datastore_fwrite(volume->metadata_store, file_handle, buffer, size)) {
        log_error("could not write metadata file\n");
        return -1;
    }

    return 0;
}

static inline int
__flush_metadata_file(struct metadata_buf * metadata_buf)
{
    struct nexus_volume * volume = metadata_buf->backend->volume;

    if (metadata_buf->backend->fsync_mode) {
        if (nexus_datastore_fflush(volume->metadata_store, metadata_buf->file_handle)) {
            log_error("nexus_datastore_fflush() FAILED\n");
            return -1;
        }
    }

    return 0;
}


static struct metadata_buf *
__io_buffer_read(struct nexus_uuid * uuid, struct stat * stat_buf, struct sgx_backend * sgx_backend)
{
    struct metadata_buf * metadata_buf = buffer_manager_find(sgx_backend->buf_manager, uuid);

    bool is_new = false;
    bool file_was_opened_here = false;


    if (metadata_buf == NULL) {
        metadata_buf = __alloc_metadata_buf(uuid, sgx_backend);
        is_new = true;
        goto read_datastore;
    }

    if (difftime(metadata_buf->timestamp, stat_buf->st_mtime) >= 0) {
        // then the metadata_buf contains up-to-date information
        goto early_exit;
    }

read_datastore:
    // if the file is empty, just set it to an empty buffer
    if (stat_buf->st_size == 0) {
        __update_metadata_buf(metadata_buf, nexus_malloc(1), 0, false);
        goto early_exit;
    }

    // try getting the file handle from a previously locked file
    if (__metadata_buf_get_handle(metadata_buf) == NULL) {
        if (__open_metadata_file(metadata_buf, NEXUS_FREAD) == NULL) {
            log_error("__open_metadata_file() FAILED\n");
            goto out_err;
        }

        file_was_opened_here = true;
    }

    if (__read_metadata_file(metadata_buf)) {
        log_error("__read_metadata_file() FAILE\n");
        goto out_err;
    }

    if (file_was_opened_here) {
        __release_metadata_buf(metadata_buf);
    }

early_exit:
    if (is_new) {
        buffer_manager_add(sgx_backend->buf_manager, metadata_buf);
    }

    return metadata_buf;

out_err:
    if (file_was_opened_here) {
        __release_metadata_buf(metadata_buf);
    }

    if (metadata_buf && is_new) {
        __free_metadata_buf(metadata_buf);
    }

    return NULL;
}

static inline struct metadata_buf *
io_buffer_read(struct nexus_uuid * uuid, struct stat * stat_buf, struct sgx_backend * sgx_backend)
{
    // TODO add BPF
    struct metadata_buf * metadata_buf = __io_buffer_read(uuid, stat_buf, sgx_backend);
    return metadata_buf;
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

    struct stat stat_buf;


    if (nexus_datastore_stat_uuid(volume->metadata_store, uuid, NULL, &stat_buf)) {
        log_error("could not stat metadata file\n");
        return NULL;
    }

    // if writing, let's lock the file
    if (flags & (NEXUS_FWRITE | NEXUS_IO_FCRYPTO)) {
        metadata_buf = io_buffer_lock(uuid, flags, volume);
        if (metadata_buf == NULL) {
            log_error("__io_buffer_lock() FAILED\n");
            return NULL;
        }
    }

    // if reading, let's check if the metadata buffer
    if (flags & NEXUS_FREAD) {
        metadata_buf = io_buffer_read(uuid, &stat_buf, sgx_backend);
        if (metadata_buf == NULL) {
            log_error("io_buffer_read() FAILED\n");
            return NULL;
        }
    }

    *p_timestamp = metadata_buf->timestamp;
    *p_size      = metadata_buf->size;

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


// writes the filenode info inside the metadata_buf's file_handle
// preconditions: file must be truncated to size
static int
__store_filenode(struct metadata_buf * metadata_buf, struct __filenode_info * filenode_info)
{
    struct nexus_file_handle * file_handle = __metadata_buf_get_handle(metadata_buf);

    size_t total_size = 0;

    int nbytes = -1;


    total_size = __filenode_total_size(filenode_info->filedata_size, metadata_buf);

    if (ftruncate(file_handle->fd, total_size)) {
        log_error("ftruncate FAILED (%s)\n", file_handle->filepath);
        return -1;
    }

    // seek to the end of the data portion (the filesize)
    if (lseek(file_handle->fd, filenode_info->filedata_size, SEEK_SET) == -1) {
        log_error("lseek on file handle FAILED\n");
        return -1;
    }

    nbytes = write(file_handle->fd, metadata_buf->addr, metadata_buf->size);

    if (nbytes != (int)metadata_buf->size) {
        log_error("could not write metadata content on file_crypto. tried=%zu, got=%d\n",
                  metadata_buf->size,
                  nbytes);
        return -1;
    }


    filenode_info->metadata_size = metadata_buf->size;

    nbytes = write(file_handle->fd, filenode_info, sizeof(struct __filenode_info));

    if (nbytes != (int)sizeof(struct __filenode_info)) {
        log_error("writing filenode_info FAILED. tried=%zu, got=%d\n",
                  sizeof(struct __filenode_info),
                  nbytes);
        return -1;
    }

    if (__flush_metadata_file(metadata_buf)) {
        log_error("flushing metadata_buf FAILED\n");
        return -1;
    }

    return 0;
}


static int
__io_buffer_filenode_put(struct metadata_buf * metadata_buf,
                         uint8_t             * buffer,
                         size_t                metadata_size,
                         size_t                data_size)
{
    struct __filenode_info filenode_info   = { .filedata_size = data_size };

    if (__store_filenode(metadata_buf, &filenode_info)) {
        log_error("__store_filenode() FAILED\n");
        return -1;
    }

    return 0;
}


static int
__io_buffer_put(struct nexus_uuid   * uuid,
                uint8_t             * buffer,
                size_t                metadata_size,
                size_t                data_size,
                size_t              * timestamp,
                struct nexus_volume * volume)
{
    struct sgx_backend  * sgx_backend  = (struct sgx_backend *)volume->private_data;

    struct metadata_buf * metadata_buf = buffer_manager_find(sgx_backend->buf_manager, uuid);

    if (metadata_buf == NULL || metadata_buf->file_handle == NULL) {
        log_error("no locked file on metadata\n");
        return -1;
    }

    if (metadata_buf->handle_flags & NEXUS_IO_FNODE) {
        if (__io_buffer_filenode_put(metadata_buf, buffer, metadata_size, data_size)) {
            log_error("__io_buffer_filenode_put() FAILED\n");
            goto out_err;
        }

        goto flush_metadata;
    }

    if (__write_metadata_file(metadata_buf, buffer, metadata_size)) {
        log_error("__write_metadata_file() FAILED\n");
        goto out_err;
    }

flush_metadata:
    if (__flush_metadata_file(metadata_buf)) {
        log_error("__flush_metadata_file() FAILED\n");
        goto out_err;
    }

    if (__release_metadata_buf(metadata_buf)) {
        log_error("__release_metadata_buf() FAILED\n");
        return -1;
    }

    __update_metadata_buf(metadata_buf, buffer, metadata_size, true);

    metadata_buf->data_size = data_size;

    *timestamp = metadata_buf->timestamp;

    return 0;

out_err:
    if (__release_metadata_buf(metadata_buf)) {
        log_error("__release_metadata_buf() FAILED\n");
    }

    return -1;
}


int
io_buffer_put(struct nexus_uuid   * uuid,
              uint8_t             * buffer,
              size_t                metadata_size,
              size_t                data_size,
              size_t              * timestamp,
              struct nexus_volume * volume)
{
    BACKEND_SGX_IOBUF_START(IOBUF_PUT);

    int ret = __io_buffer_put(uuid, buffer, metadata_size, data_size, timestamp, volume);

    BACKEND_SGX_IOBUF_FINISH(IOBUF_PUT);

    return ret;
}

static inline struct metadata_buf *
__io_buffer_lock(struct nexus_uuid * uuid, nexus_io_flags_t flags, struct nexus_volume * volume)
{
    struct sgx_backend  * sgx_backend  = (struct sgx_backend *)volume->private_data;

    struct metadata_buf * metadata_buf = buffer_manager_find(sgx_backend->buf_manager, uuid);

    if (metadata_buf == NULL) {
        metadata_buf = __alloc_metadata_buf(uuid, sgx_backend);
        buffer_manager_add(sgx_backend->buf_manager, metadata_buf);
    }

    if (__open_metadata_file(metadata_buf, flags) == NULL) {
        log_error("nexus_datastore_fopen FAILED\n");
        return NULL;
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

    if (metadata_buf && metadata_buf->file_handle) {
        __release_metadata_buf(metadata_buf);

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
        log_error("could not statmetadata file\n");
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


    file_crypto->file_handle = __metadata_buf_get_handle(file_crypto->metadata_buf);

    if (file_crypto->file_handle == NULL) {
        log_error("__metadata_buf_get_handle() returned NULL for %s\n", filepath);
        nexus_free(file_crypto);
        return NULL;
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
    if (lseek(file_crypto->file_handle->fd, offset, SEEK_SET) == -1) {
        return -1;
    }

    file_crypto->offset = offset;

    return 0;
}

int
io_file_crypto_read(struct nexus_file_crypto * file_crypto, uint8_t * output_buffer, size_t nbytes)
{
    int bytes_read = read(file_crypto->file_handle->fd, output_buffer, nbytes);

    if (bytes_read != (int)nbytes) {
        log_error("reading file (%s) failed. tried=%zu, got=%d\n",
                  file_crypto->file_handle->filepath,
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
    int bytes_written = write(file_crypto->file_handle->fd, (uint8_t *)input_buffer, nbytes);

    if (bytes_written != (int)nbytes) {
        log_error("writing file (%s) failed. tried=%zu, got=%d\n",
                  file_crypto->file_handle->filepath,
                  nbytes,
                  bytes_written);
        return -1;
    }

    file_crypto->offset += bytes_written;

    return 0;
}

int
io_file_crypto_finish(struct nexus_file_crypto * file_crypto)
{
    nexus_free(file_crypto->filepath);
    nexus_free(file_crypto);

    return 0;
}
