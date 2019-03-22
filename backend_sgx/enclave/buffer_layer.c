#include "enclave_internal.h"


struct metadata_buffer {
    int                    writers;

    bool                   is_dirty;

    struct nexus_uuid      uuid;

    nexus_io_flags_t       flags;

    size_t                 timestamp;

    uint8_t              * tmp_buffer;

    size_t                 tmp_buflen;

    sgx_spinlock_t         write_lock;
};


/* the buffer cache is a hashatable of <uuid, metadata_buffer> pairs */
static struct nexus_hashtable * buffer_cache = NULL;

static sgx_spinlock_t           bcache_lock  = SGX_SPINLOCK_INITIALIZER;

static size_t                   buffer_count = 0;



static inline struct metadata_buffer *
__bcache_get(struct nexus_uuid * uuid)
{
    return (struct metadata_buffer *)nexus_htable_search(buffer_cache, (uintptr_t)uuid);
}


static inline bool
__in_write_mode(struct metadata_buffer * meta_buf)
{
    return nexus_io_in_lock_mode(meta_buf->flags);
}

static void
__metadata_buf_update(struct metadata_buffer * metadata_buf,
                      size_t                   timestamp,
                      nexus_io_flags_t         flags)
{
    if (timestamp) {
        metadata_buf->timestamp = timestamp;
    }

    metadata_buf->flags     = flags;
}

static struct metadata_buffer *
__bcache_update(struct nexus_uuid * uuid, size_t timestamp, nexus_io_flags_t flags)
{
    struct metadata_buffer * metadata_buf = NULL;

    sgx_spin_lock(&bcache_lock);

    metadata_buf = __bcache_get(uuid);

    if (metadata_buf == NULL) {
        metadata_buf =  nexus_malloc(sizeof(struct metadata_buffer));

        nexus_uuid_copy(uuid, &metadata_buf->uuid);

        nexus_htable_insert(buffer_cache, (uintptr_t)&metadata_buf->uuid, (uintptr_t)metadata_buf);

        metadata_buf->write_lock = SGX_SPINLOCK_INITIALIZER;

        buffer_count += 1;
    }

    __metadata_buf_update(metadata_buf, timestamp, flags);

    sgx_spin_unlock(&bcache_lock);

    return metadata_buf;
}

static inline void
__bcache_evict(struct nexus_uuid * uuid)
{
    struct metadata_buffer * meta_buf = NULL;

    sgx_spin_lock(&bcache_lock);
    meta_buf = (struct metadata_buffer *)nexus_htable_remove(buffer_cache, (uintptr_t)uuid, 0);

    if (meta_buf) {
        nexus_free(meta_buf);
        buffer_count -= 1;
    }

    sgx_spin_unlock(&bcache_lock);
}

int
buffer_layer_init()
{
    buffer_cache = nexus_create_htable(17, __uuid_hasher, __uuid_equals);

    return 0;
}

int
buffer_layer_exit()
{
    // TODO clear the buffer cache
    nexus_free_htable(buffer_cache, 1, 0);
    return 0;
}

void
buffer_layer_evict(struct nexus_uuid * uuid)
{
    __bcache_evict(uuid);
}

int
buffer_layer_revalidate(struct nexus_uuid * uuid, bool * should_reload)
{
    struct metadata_buffer * meta_buf = NULL;

    size_t stat_timestamp;


    // check if we have a timestamp
    meta_buf = (struct metadata_buffer *)nexus_htable_search(buffer_cache, (uintptr_t)uuid);

    if (meta_buf == NULL) {
        *should_reload = true;
        return 0;
    }

    // stat the datastore
    {
        int err = -1;
        int ret = -1;

        err = ocall_buffer_stattime(&ret, uuid, &stat_timestamp, global_volume);

        if (err || ret) {
            log_error("ocall_buffer_stattime FAILED (err=%d, ret=%d)\n", err, ret);
            return -1;
        }
    }

    *should_reload = stat_timestamp > meta_buf->timestamp;

    return 0;
}

uint8_t *
buffer_layer_alloc(struct nexus_uuid * uuid, size_t size)
{
    struct metadata_buffer * meta_buf = __bcache_get(uuid);

    if (meta_buf == NULL || !__in_write_mode(meta_buf)) {
        log_error("meta_buf not found or not in write mode\n");
        return NULL;
    }

    sgx_spin_lock(&meta_buf->write_lock);

    if (meta_buf->tmp_buffer) {
        nexus_heap_free(global_heap, meta_buf->tmp_buffer);
        meta_buf->tmp_buffer = NULL;
    }

    meta_buf->tmp_buffer = nexus_heap_malloc(global_heap, size);
    if (meta_buf->tmp_buffer == NULL) {
        log_error("could not allocate memory (size=%zu)\n", size);
        sgx_spin_unlock(&meta_buf->write_lock);
        return NULL;
    }

    meta_buf->tmp_buflen = size;

    return meta_buf->tmp_buffer;
}

int
buffer_layer_dealloc(struct nexus_uuid * uuid)
{
    struct metadata_buffer * meta_buf = __bcache_get(uuid);

    if (meta_buf == NULL || !__in_write_mode(meta_buf)) {
        return -1;
    }

    nexus_heap_free(global_heap, meta_buf->tmp_buffer);

    meta_buf->tmp_buffer = NULL;
    meta_buf->tmp_buflen = 0;

    sgx_spin_unlock(&meta_buf->write_lock);

    return 0;
}

int
buffer_layer_lock(struct nexus_uuid * uuid, nexus_io_flags_t flags)
{
    struct metadata_buffer * meta_buf = __bcache_get(uuid);

    int err = -1;
    int ret = -1;

    // prevent double locking
    if (meta_buf && __in_write_mode(meta_buf)) {
        meta_buf->writers += 1;
        return 0;
    }

    err = ocall_buffer_lock(&ret, uuid, flags, global_volume);

    if (err || ret) {
        log_error("ocall_buffer_lock FAILED (err=%d, ret=%d)\n", err, ret);
        return -1;
    }

    meta_buf = __bcache_update(uuid, 0, flags);
    if (meta_buf && __in_write_mode(meta_buf)) {
        meta_buf->writers += 1;
    }

    return 0;
}

int
buffer_layer_unlock(struct nexus_uuid * uuid)
{
    struct metadata_buffer * meta_buf = __bcache_get(uuid);

    int err = -1;
    int ret = -1;

    if (meta_buf == NULL || !__in_write_mode(meta_buf)) {
        return 0;
    }

    // prevent double locking
    if (meta_buf->writers == 0) {
        log_error("trying to unlock a file with no writers\n");
        return -1;
    }

    meta_buf->writers -= 1;

    if (meta_buf->writers) {
        return 0;
    }

    err = ocall_buffer_unlock(&ret, uuid, global_volume);

    if (err) {
        log_error("ocall_buffer_unlock FAILED (err=%d, ret=%d)\n", err, ret);
        return -1;
    }

    __metadata_buf_update(meta_buf, 0, NEXUS_FREAD);

    return ret;
}

int
buffer_layer_lock_status(struct nexus_uuid * uuid, nexus_io_flags_t * flags)
{
    struct metadata_buffer * meta_buf = __bcache_get(uuid);

    if (meta_buf == NULL) {
        return -1;
    }

    *flags = meta_buf->flags;
    return 0;
}

void *
buffer_layer_get(struct nexus_uuid * uuid, nexus_io_flags_t flags, size_t * size)
{
    struct metadata_buffer * meta_buf = __bcache_get(uuid);

    uint8_t * external_addr = NULL;

    size_t    timestamp     = 0;

    int err = -1;


    if (meta_buf && meta_buf->is_dirty) {
        *size = meta_buf->tmp_buflen;
        return meta_buf->tmp_buffer;
    }


    err = ocall_buffer_get(&external_addr, uuid, flags, size, &timestamp, global_volume);

    if (err || external_addr == NULL) {
        log_error("ocall_buffer_get FAILED (err=%d)\n", err);
        return NULL;
    }


    meta_buf = __bcache_update(uuid, timestamp, flags);

    if (__in_write_mode(meta_buf)) {
        meta_buf->writers += 1;
    }

    return external_addr;
}

int
buffer_layer_put(struct nexus_uuid * uuid, size_t data_size)
{
    struct metadata_buffer * meta_buf = NULL;

    size_t timestamp = 0;


    // get the metadata buffer from the cache and write it to disk
    meta_buf = __bcache_get(uuid);

    if (meta_buf == NULL || meta_buf->tmp_buffer == NULL) {
        return -1;
    }


    // no need to flush the buffer, as there will be another on the way
    if (meta_buf->writers > 1) {
        meta_buf->is_dirty = true;
        meta_buf->writers -= 1;
        sgx_spin_unlock(&meta_buf->write_lock);
        return 0;
    }


    {
        int ret = -1;
        int err = ocall_buffer_put(&ret,
                                   uuid,
                                   meta_buf->tmp_buffer,
                                   meta_buf->tmp_buflen,
                                   data_size,
                                   &timestamp,
                                   global_volume);

        buffer_layer_dealloc(uuid);

        if (err || ret) {
            log_error("ocall_buffer_put FAILED (err=%d, ret=%d)\n", err, ret);
            sgx_spin_unlock(&meta_buf->write_lock);
            return -1;
        }

        __metadata_buf_update(meta_buf, timestamp, NEXUS_FREAD);
    }

    meta_buf->writers = 0;

    sgx_spin_unlock(&meta_buf->write_lock);

    return 0;
}

int
buffer_layer_new(struct nexus_uuid * uuid)
{
    int err = -1;
    int ret = -1;

    err = ocall_buffer_new(&ret, uuid, global_volume);

    if (err || ret) {
        log_error("ocall_buffer_new FAILED (err=%d, ret=%d)\n", err, ret);
        return -1;
    }

    return 0;
}

int
buffer_layer_delete(struct nexus_uuid * uuid)
{
    int err = -1;
    int ret = -1;

    buffer_layer_evict(uuid);

    err = ocall_buffer_del(&ret, uuid, global_volume);

    // XXX: what do to about err?
    (void) ret;

    if (err) {
        log_error("ocall_buffer_del FAILED\n");
        return -1;
    }

    return 0;
}
