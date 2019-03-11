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
    if (metadata_buf->buffer_addr) {
        nexus_free(metadata_buf->buffer_addr);
    }

    nexus_free(metadata_buf);
}

static void
__update_metadata_buf(struct metadata_buf * buf, uint8_t * ptr, size_t size, bool copy)
{
    if (buf->buffer_addr) {
        nexus_free(buf->buffer_addr);
    }

    if (copy) {
        buf->buffer_addr = nexus_malloc(size);
        memcpy(buf->buffer_addr, ptr, size);
    } else {
        buf->buffer_addr = ptr;
    }

    buf->buffer_size = size;

    // the last time we "synced" buffer
    buf->buffer_time = time(NULL);
}

void
__metadata_update_sync_time(struct metadata_buf * metadata_buf)
{
    metadata_buf->sync_time = time(NULL);
}

static struct nexus_datastore *
__get_backend_datastore(struct nexus_volume * volume)
{
    struct sgx_backend * backend = (struct sgx_backend*)volume->private_data;

    if (backend->batch_mode) {
        return backend->batch_datastore;
    }

    return volume->metadata_store;
}

static struct nexus_file_handle *
__metadata_buf_get_handle(struct metadata_buf * metadata_buf)
{
    if (metadata_buf->backend->batch_mode && !(metadata_buf->is_syncing)) {
        return metadata_buf->batch_handle;
    }

    return metadata_buf->file_handle;
}

static struct nexus_datastore *
__metadata_buf_get_datastore(struct metadata_buf * metadata_buf)
{
    if (metadata_buf->backend->batch_mode && !(metadata_buf->is_syncing)) {
        return metadata_buf->backend->batch_datastore;
    }

    return metadata_buf->backend->volume->metadata_store;
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

    if (nexus_io_in_lock_mode(metadata_buf->io_flags)) {
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
    struct nexus_datastore   * datastore   = __metadata_buf_get_datastore(metadata_buf);
    struct nexus_file_handle * file_handle = __metadata_buf_get_handle(metadata_buf);

    bool was_synced = false;

    nexus_io_flags_t flags;

    int ret = -1;

    if (file_handle == NULL) {
        // XXX log a warning here
        return 0;
    }

    flags = metadata_buf->io_flags;

    ret = nexus_datastore_fclose(datastore, file_handle);
    if (ret != 0) {
        log_error("nexus_datastore_fclose() FAILED\n");
    }

    if (metadata_buf->file_handle) {
        was_synced = true;
    }

    metadata_buf->file_handle  = NULL;
    metadata_buf->batch_handle = NULL;

    metadata_buf->io_flags     = 0;
    metadata_buf->is_dirty     = false;

    if (nexus_io_in_lock_mode(flags)) {
        if (ret == 0 && was_synced) {
            __metadata_update_sync_time(metadata_buf);
        }

        metadata_buf->flush_time = time(NULL);

        pthread_mutex_unlock(&metadata_buf->file_mutex);
    }

    return ret;
}


static int
__copy_metadata_file_to_batch_directory(struct metadata_buf * metadata_buf, bool check_exists)
{
    struct nexus_datastore * src_datastore = metadata_buf->backend->volume->metadata_store;
    struct nexus_datastore * dst_datastore = metadata_buf->backend->batch_datastore;

    if (check_exists && metadata_buf->batch_file_exists) {
        return 0;
    }

    if (nexus_datastore_copy_uuid(src_datastore, dst_datastore, &metadata_buf->uuid, true)) {
        log_error("nexus_datastore_copy_uuid() FAIlED\n");
        return -1;
    }

    metadata_buf->batch_file_exists = true;

    metadata_buf->sync_file_exists = true;

    return 0;
}

static struct nexus_file_handle *
__open_metadata_file(struct metadata_buf * metadata_buf, nexus_io_flags_t flags)
{
    struct nexus_datastore   * datastore   = __metadata_buf_get_datastore(metadata_buf);
    struct nexus_file_handle * file_handle = __metadata_buf_get_handle(metadata_buf);

    if (file_handle) {
        if ((flags & metadata_buf->io_flags) != flags) {
            log_error("metadata already has locked file with incompatible flags\n");
            return NULL;
        }

        return __acquire_metadata_buf(metadata_buf);
    }

    if ((metadata_buf->backend->batch_mode) && !(flags & NEXUS_FCREATE)) {
        if (!(metadata_buf->is_syncing) && !(metadata_buf->batch_mode_created)) {
            if (__copy_metadata_file_to_batch_directory(metadata_buf, true)) {
                log_error("__copy_metadata_file_to_batch_directory() FAILED\n");
                return NULL;
            }
        }
    }

    file_handle = nexus_datastore_fopen(datastore, &metadata_buf->uuid, NULL, flags);

    if (file_handle == NULL) {
        log_error("nexus_datastore_fopen FAILED\n");
        return NULL;
    }

    if (metadata_buf->backend->batch_mode && !(metadata_buf->is_syncing)) {
        metadata_buf->batch_handle = file_handle;
    } else {
        metadata_buf->file_handle = file_handle;
    }

    metadata_buf->io_flags = flags;

    if ((datastore == metadata_buf->backend->batch_datastore) && (flags & NEXUS_FCREATE)) {
        metadata_buf->batch_mode_created  = true;
        metadata_buf->batch_file_exists   = true;
    } else if (datastore == metadata_buf->backend->volume->metadata_store) {
        metadata_buf->sync_file_exists = true;
    }

    return __acquire_metadata_buf(metadata_buf);
}


static inline int
__read_metadata_file(struct metadata_buf * metadata_buf)
{
    struct nexus_datastore   * datastore   = __metadata_buf_get_datastore(metadata_buf);
    struct nexus_file_handle * file_handle = __metadata_buf_get_handle(metadata_buf);
    nexus_io_flags_t           flags       = metadata_buf->io_flags;

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

    if (nexus_datastore_fread(datastore, file_handle, &addr, &size)) {
        log_error("nexus_datastore_fread FAILED\n");
        return -1;
    }

    __update_metadata_buf(metadata_buf, addr, size, false);

    return 0;
}

static inline int
__write_metadata_file(struct metadata_buf * metadata_buf, uint8_t * buffer, size_t size)
{
    struct nexus_datastore   * datastore   = __metadata_buf_get_datastore(metadata_buf);
    struct nexus_file_handle * file_handle = __metadata_buf_get_handle(metadata_buf);

    if (nexus_datastore_fwrite(datastore, file_handle, buffer, size)) {
        log_error("could not write metadata file\n");
        return -1;
    }

    return 0;
}

static inline int
__flush_metadata_file(struct metadata_buf * metadata_buf)
{
    struct nexus_datastore   * datastore   = __metadata_buf_get_datastore(metadata_buf);
    struct nexus_file_handle * file_handle = __metadata_buf_get_handle(metadata_buf);

    if ((metadata_buf->backend->batch_mode) && (metadata_buf->is_syncing == false)) {
        metadata_buf->is_dirty = true;
        return 0;
    }

    if (metadata_buf->backend->fsync_mode) {
        if (nexus_datastore_fflush(datastore, file_handle)) {
            log_error("nexus_datastore_fflush() FAILED\n");
            return -1;
        }
    }

    metadata_buf->is_dirty = false;

    return 0;
}

static struct metadata_buf *
__io_buffer_read(struct nexus_uuid  * uuid,
                 nexus_io_flags_t     flags,
                 struct stat        * stat_buf,
                 struct sgx_backend * sgx_backend)
{
    struct metadata_buf * metadata_buf = buffer_manager_find(sgx_backend->buf_manager, uuid);

    bool is_new = false;
    bool file_was_opened_here = false;


    if (metadata_buf == NULL) {
        metadata_buf = __alloc_metadata_buf(uuid, sgx_backend);
        is_new = true;
        goto read_datastore;
    }

    if (metadata_buf->is_dirty) {
        goto early_exit;
    }

    if (difftime(metadata_buf->buffer_time, stat_buf->st_mtime) >= 0) {
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
        if (__open_metadata_file(metadata_buf, flags) == NULL) {
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
io_buffer_read(struct nexus_uuid  * uuid,
               nexus_io_flags_t     flags,
               struct stat        * stat_buf,
               struct sgx_backend * sgx_backend)
{
    // TODO add BPF
    struct metadata_buf * metadata_buf = __io_buffer_read(uuid, flags, stat_buf, sgx_backend);
    return metadata_buf;
}

static inline uint8_t *
__io_buffer_get(struct nexus_uuid   * uuid,
                nexus_io_flags_t      flags,
                size_t              * p_size,
                size_t              * p_timestamp,
                struct nexus_volume * volume)
{
    struct nexus_datastore   * datastore    = NULL;
    struct sgx_backend       * sgx_backend  = (struct sgx_backend *)volume->private_data;

    struct metadata_buf      * metadata_buf = NULL;

    struct stat stat_buf;


    datastore = io_backend_get_datastore(volume, uuid, &metadata_buf);

    if (nexus_datastore_stat_uuid(datastore, uuid, NULL, &stat_buf)) {
        log_error("could not stat metadata file\n");
        return NULL;
    }

    // if writing, let's lock the file
    if (flags & (NEXUS_FWRITE | NEXUS_IO_FCRYPTO)) {
        metadata_buf = io_buffer_lock(uuid, flags, volume);
        if (metadata_buf == NULL) {
            log_error("io_buffer_lock() FAILED\n");
            return NULL;
        }
    }

    if (flags & NEXUS_FREAD) {
        metadata_buf = io_buffer_read(uuid, flags, &stat_buf, sgx_backend);
        if (metadata_buf == NULL) {
            log_error("io_buffer_read() FAILED\n");
            return NULL;
        }
    }

    *p_timestamp = metadata_buf->buffer_time;
    *p_size      = metadata_buf->buffer_size;

    return metadata_buf->buffer_addr;
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


static inline size_t
__filenode_total_size(struct __filenode_info * info)
{
    return info->metadata_size + info->filedata_size + sizeof(struct __filenode_info);
}

// writes the filenode info inside the metadata_buf's file_handle
// preconditions: file must be truncated to size
static int
__store_filenode(struct nexus_file_handle * file_handle,
                 uint8_t                  * buffer,
                 size_t                     metadata_size,
                 size_t                     data_size)
{
    struct __filenode_info filenode_info = { 0 };

    size_t total_size = 0;

    int nbytes = -1;


    filenode_info.metadata_size = metadata_size;
    filenode_info.filedata_size = data_size;

    total_size = __filenode_total_size(&filenode_info);

    if (ftruncate(file_handle->fd, total_size)) {
        log_error("ftruncate FAILED (%s)\n", file_handle->filepath);
        return -1;
    }

    // seek to the end of the data portion (the filesize)
    if (lseek(file_handle->fd, filenode_info.filedata_size, SEEK_SET) == -1) {
        log_error("lseek on file handle FAILED\n");
        return -1;
    }

    nbytes = write(file_handle->fd, buffer, metadata_size);

    if (nbytes != (int)metadata_size) {
        log_error("could not write metadata content on file_crypto. tried=%zu, got=%d\n",
                  metadata_size,
                  nbytes);
        return -1;
    }

    nbytes = write(file_handle->fd, &filenode_info, sizeof(struct __filenode_info));

    if (nbytes != (int)sizeof(struct __filenode_info)) {
        log_error("writing filenode_info FAILED. tried=%zu, got=%d\n",
                  sizeof(struct __filenode_info),
                  nbytes);
        return -1;
    }

    return 0;
}


static int
__io_buffer_store_filenode(struct metadata_buf * metadata_buf,
                           uint8_t             * buffer,
                           size_t                metadata_size,
                           size_t                data_size)
{
    struct nexus_file_handle * file_handle = __metadata_buf_get_handle(metadata_buf);

    if (__store_filenode(file_handle, buffer, metadata_size, data_size)) {
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

    bool metadata_stays_dirty = false;


    if (metadata_buf == NULL || __metadata_buf_get_handle(metadata_buf) == NULL) {
        log_error("no locked file on metadata\n");
        return -1;
    }

    if (metadata_buf->io_flags & NEXUS_IO_FNODE) {
        if (__io_buffer_store_filenode(metadata_buf, buffer, metadata_size, data_size)) {
            log_error("__io_buffer_filenode_put() FAILED\n");
            goto out_err;
        }
    } else {
        if (sgx_backend->batch_mode) {
            metadata_stays_dirty = true;
            goto flush_metadata;
        }

        // we are writing a regular metadata file (e.g. dirnode)
        if (__write_metadata_file(metadata_buf, buffer, metadata_size)) {
            log_error("__write_metadata_file() FAILED\n");
            goto out_err;
        }
    }

flush_metadata:
    if (sgx_backend->batch_mode) {
        metadata_buf->batch_mode_modified = true;
    }

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
    metadata_buf->is_dirty  = metadata_stays_dirty;

    *timestamp = metadata_buf->buffer_time;

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
        log_error("__open_metadata_file FAILED\n");
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

    if (metadata_buf &&  __release_metadata_buf(metadata_buf)) {
        log_error("__release_metadata_buf FAILED\n");
        return NULL;
    }

    return metadata_buf;
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

static inline int
__io_buffer_new(struct nexus_uuid * metadata_uuid, struct nexus_volume * volume)
{
    struct sgx_backend     * backend      = (struct sgx_backend *)volume->private_data;
    struct nexus_datastore * datastore    = __get_backend_datastore(volume);
    struct metadata_buf    * metadata_buf = NULL;


    if (nexus_datastore_new_uuid(datastore, metadata_uuid, NULL)) {
        return -1;
    }

    if (datastore == backend->batch_datastore) {
        metadata_buf = __alloc_metadata_buf(metadata_uuid, backend);

        metadata_buf->batch_mode_created  = true;
        metadata_buf->batch_mode_modified = true;
        metadata_buf->batch_file_exists   = true;
        metadata_buf->flush_time          = time(NULL);

        buffer_manager_add(backend->buf_manager, metadata_buf);
    }

    return 0;
}

int
io_buffer_new(struct nexus_uuid * metadata_uuid, struct nexus_volume * volume)
{
    int result = -1;

    BACKEND_SGX_IOBUF_START(IOBUF_NEW);

    result = __io_buffer_new(metadata_uuid, volume);

    BACKEND_SGX_IOBUF_FINISH(IOBUF_NEW);

    return result;
}

static inline int
__io_buffer_del(struct nexus_uuid * metadata_uuid, struct nexus_volume * volume)
{
    struct sgx_backend     * backend      = (struct sgx_backend *)volume->private_data;
    struct nexus_datastore * datastore    = __get_backend_datastore(volume);
    struct metadata_buf    * metadata_buf = buffer_manager_find(backend->buf_manager, metadata_uuid);

    if (metadata_buf && backend->batch_mode && metadata_buf->sync_file_exists) {
        struct nexus_uuid * uuid = nexus_uuid_clone(metadata_uuid);
        nexus_list_append(&backend->batch_deleted_uuids, uuid);
    }

    buffer_manager_del(backend->buf_manager, metadata_uuid);

    if (nexus_datastore_del_uuid(datastore, metadata_uuid, NULL)) {
        return -1;
    }

    return 0;
}

int
io_buffer_del(struct nexus_uuid * metadata_uuid, struct nexus_volume * volume)
{
    int result = -1;

    BACKEND_SGX_IOBUF_START(IOBUF_DEL);

    result = __io_buffer_del(metadata_uuid, volume);

    BACKEND_SGX_IOBUF_FINISH(IOBUF_DEL);

    return result;
}

struct nexus_datastore *
io_backend_get_datastore(struct nexus_volume * volume, struct nexus_uuid * uuid, struct metadata_buf ** buf)
{
    struct sgx_backend * backend = volume->private_data;

    struct metadata_buf * metadata_buf = NULL;

    if (!backend->batch_mode) {
        return volume->metadata_store;
    }

    metadata_buf = buffer_manager_find(backend->buf_manager, uuid);

    if (buf) {
        *buf = metadata_buf;
    }

    if (metadata_buf == NULL || metadata_buf->batch_file_exists == false) {
        return volume->metadata_store;
    }

    return backend->batch_datastore;
}

int
io_backend_stat_uuid(struct nexus_volume  * volume,
                     struct nexus_uuid    * uuid,
                     struct nexus_fs_attr * attrs)
{
    struct metadata_buf    * metadata_buf = NULL;

    struct nexus_datastore * datastore = io_backend_get_datastore(volume, uuid, &metadata_buf);

    if (datastore == NULL) {
        log_error("io_backend_get_datastore() FAILED\n");
        return -1;
    }

    if (nexus_datastore_getattr(datastore, uuid, attrs)) {
        log_error("nexus_datastore_getattr() FAILED\n");
        return -1;
    }

    if (metadata_buf && metadata_buf->is_dirty) {
        attrs->posix_stat.st_mtime = metadata_buf->buffer_time;
    }

    return 0;
}

static int
__io_buffer_stattime(struct nexus_uuid * uuid, size_t * timestamp, struct nexus_volume * volume)
{
    struct nexus_fs_attr attrs;

    if (io_backend_stat_uuid(volume, uuid, &attrs)) {
        log_error("io_backend_stat_uuid() FAILED\n");
        return -1;
    }

    *timestamp = attrs.posix_stat.st_mtime;

    return 0;
}

int
io_buffer_stattime(struct nexus_uuid * uuid, size_t * timestamp, struct nexus_volume * volume)
{
    int result = -1;

    BACKEND_SGX_IOBUF_START(IOBUF_STAT);

    result = __io_buffer_stattime(uuid, timestamp, volume);

    BACKEND_SGX_IOBUF_FINISH(IOBUF_STAT);

    return result;
}


// metadata syncing stuff

static int
__sync_on_disk_metadata(struct metadata_buf * metadata_buf)
{
    struct nexus_datastore * src_datastore = metadata_buf->backend->batch_datastore;
    struct nexus_datastore * dst_datastore = metadata_buf->backend->volume->metadata_store;

    if (nexus_datastore_copy_uuid(src_datastore, dst_datastore, &metadata_buf->uuid, true)) {
        log_error("nexus_datastore_copy_uuid() FAIlED\n");
        return -1;
    }

    __metadata_update_sync_time(metadata_buf);

    return 0;
}

static int
__sync_in_memory_metadata(struct metadata_buf * metadata_buf)
{
    nexus_io_flags_t flags = NEXUS_FWRITE;

    if (metadata_buf->batch_mode_created) {
        flags |= NEXUS_FCREATE;
    }

    if (__open_metadata_file(metadata_buf, flags) == NULL) {
        log_error("openning metadata file failed\n");
        return -1;
    }

    if (__write_metadata_file(metadata_buf, metadata_buf->buffer_addr, metadata_buf->buffer_size)) {
        log_error("__write_metadata_file() FAILED\n");
        goto out_err;
    }

    if (__flush_metadata_file(metadata_buf)) {
        log_error("__flush_metadata_file() FAILED\n");
        goto out_err;
    }

    if (__release_metadata_buf(metadata_buf)) {
        log_error("__release_metadata_buf() FAILED\n");
        return -1;
    }

    return 0;

out_err:
    __release_metadata_buf(metadata_buf);
    return -1;
}

static inline int
__sync_deleted_uuids(struct sgx_backend * backend)
{
    struct nexus_list_iterator * iter = list_iterator_new(&backend->batch_deleted_uuids);

    while (list_iterator_is_valid(iter)) {
        struct nexus_uuid * uuid = list_iterator_get(iter);

        nexus_datastore_del_uuid(backend->volume->metadata_store, uuid, NULL);

        list_iterator_del(iter);
    }

    list_iterator_free(iter);

    return 0;
}

static inline int
__io_buffer_sync_buffers(struct sgx_backend * backend)
{
    struct metadata_buf * metadata_buf = NULL;
    struct nexus_hashtable_iter * iter = NULL;

    int flush_count = 0;
    double flush_time = 0;

    struct timespec t1, t2;

    int ret = -1;


    if (backend->batch_mode == false) {
        return 0;
    }

    iter = nexus_htable_create_iter(backend->buf_manager->buffers_table);
    if (iter->entry == NULL) {
        ret = 0;
        goto out;
    }


    clock_gettime(CLOCK_MONOTONIC, &t1);

    do {
        ret = 0;

        metadata_buf = (struct metadata_buf *)nexus_htable_get_iter_value(iter);

        if (!metadata_buf->batch_mode_modified) {
            continue;
        }

        metadata_buf->is_syncing = true;

        if (metadata_buf->is_dirty) {
            ret = __sync_in_memory_metadata(metadata_buf);
        } else {
            ret = __sync_on_disk_metadata(metadata_buf);
        }

        metadata_buf->is_syncing = false;

        metadata_buf->batch_mode_created = false;
        metadata_buf->batch_file_exists = false;
        metadata_buf->batch_mode_modified = false;

        if (ret != 0) {
            log_error("could not flush metadata file\n");
            goto out;
        }

        flush_count += 1;
    } while (nexus_htable_iter_advance(iter));


    if (__sync_deleted_uuids(backend)) {
        log_error("__sync_deleted_uuids() FAILED\n");
        goto out;
    }

    ret = 0;
out:
    clock_gettime(CLOCK_MONOTONIC, &t2);
    flush_time = (((t2.tv_sec - t1.tv_sec) * 1e9) + (t2.tv_nsec - t1.tv_nsec)) / 1e9;

    nexus_printf("io_sync_buffers: time=%.6fs count=%d\n", flush_time, flush_count);

    nexus_htable_free_iter(iter);

    return ret;
}


// condition: must hold backend->batch_mutex
int
io_buffer_sync_buffers(struct sgx_backend * backend)
{
    return __io_buffer_sync_buffers(backend);
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
