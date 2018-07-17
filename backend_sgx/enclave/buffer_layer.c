#include "enclave_internal.h"


struct metadata_info {
    struct nexus_uuid      uuid;

    nexus_io_flags_t       flags;

    size_t                 timestamp;

    uint8_t              * tmp_buffer; // used for "flush" operations

    size_t                 tmp_buflen;
};


static struct nexus_hashtable * metadata_info_htable = NULL;


int
buffer_layer_init()
{
    metadata_info_htable = nexus_create_htable(17, __uuid_hasher, __uuid_equals);

    return 0;
}

int
buffer_layer_exit()
{
    nexus_free_htable(metadata_info_htable, 1, 0);
    return 0;
}

static struct metadata_info *
__update_timestamp(struct nexus_uuid * uuid, size_t timestamp, nexus_io_flags_t flags)
{
    struct metadata_info * info = NULL;

    info = (struct metadata_info *)nexus_htable_search(metadata_info_htable, (uintptr_t)uuid);

    if (info == NULL) {
        info =  nexus_malloc(sizeof(struct metadata_info));

        nexus_uuid_copy(uuid, &info->uuid);

        nexus_htable_insert(metadata_info_htable, (uintptr_t)&info->uuid, (uintptr_t)info);
    }

    info->timestamp = timestamp;
    info->flags     = flags;

    return info;
}

void
buffer_layer_evict(struct nexus_uuid * uuid)
{
    struct metadata_info * info = NULL;

    info = (struct metadata_info *)nexus_htable_remove(metadata_info_htable, (uintptr_t)uuid, 0);

    nexus_free(info);
}

int
buffer_layer_revalidate(struct nexus_uuid * uuid, bool * should_reload)
{
    struct metadata_info * info    = NULL;

    size_t stat_timestamp;

    int err = -1;
    int ret = -1;

    // check if we have a timestamp
    info = (struct metadata_info *)nexus_htable_search(metadata_info_htable, (uintptr_t)uuid);

    if (info == NULL) {
        *should_reload = true;
        return 0;
    }

    err = ocall_buffer_stattime(&ret, uuid, &stat_timestamp, global_volume);

    if (err || ret) {
        log_error("ocall_buffer_stat FAILED (err=%d, ret=%d)\n", err, ret);
        return -1;
    }

    *should_reload = stat_timestamp > info->timestamp;

    return 0;
}

uint8_t *
buffer_layer_alloc(struct nexus_uuid * uuid, size_t size)
{
    struct metadata_info * info = NULL;

    uint8_t              * addr = nexus_heap_malloc(global_heap, size);

    if (addr == NULL) {
        log_error("could not allocate memory (size=%zu)\n", size);
        return NULL;
    }


    info = (struct metadata_info *)nexus_htable_search(metadata_info_htable, (uintptr_t)uuid);

    // this means that the file has been requested in a previous get with FWRITE
    if (info && info->flags & NEXUS_FWRITE) {
        info->tmp_buffer = addr;
        info->tmp_buflen = size;

        return addr;
    }

    /* this branch accounts for metadata which have not been written to disk.
     * Examples include: newly created chunks */

    // lock the file and insert into metadata table
    {
        int ret = -1;
        int err = ocall_buffer_lock(&ret, uuid, global_volume);

        if (err || ret) {
            nexus_heap_free(global_heap, addr);

            log_error("ocall_buffer_alloc FAILED (err=%d, ret=%d)\n", err, ret);
            return NULL;
        }
    }

    info = __update_timestamp(uuid, 0, NEXUS_FWRITE);

    info->tmp_buffer = addr;
    info->tmp_buflen = size;

    return addr;
}

int
buffer_layer_lock(struct nexus_uuid * uuid)
{
    int err = -1;
    int ret = -1;

    err = ocall_buffer_lock(&ret, uuid, global_volume);

    if (err || ret) {
        log_error("ocall_buffer_lock FAILED (err=%d, ret=%d)\n", err, ret);
        return -1;
    }

    __update_timestamp(uuid, 0, NEXUS_FWRITE);

    return 0;
}

void *
buffer_layer_get(struct nexus_uuid * uuid, nexus_io_flags_t flags, size_t * size)
{
    uint8_t * external_addr = NULL;

    size_t    timestamp     = 0;

    int err = -1;


    err = ocall_buffer_get(&external_addr, uuid, flags, size, &timestamp, global_volume);

    if (err || external_addr == NULL) {
        log_error("ocall_buffer_get FAILED (err=%d)\n", err);
        return NULL;
    }

    __update_timestamp(uuid, timestamp, flags);

    return external_addr;
}

int
buffer_layer_put(struct nexus_uuid * buffer_uuid)
{
    struct metadata_info * info = NULL;

    info = (struct metadata_info *)nexus_htable_search(metadata_info_htable,
                                                       (uintptr_t)buffer_uuid);

    size_t timestamp = 0;

    if (info && info->tmp_buffer) {
        int ret = -1;
        int err = ocall_buffer_put(&ret,
                                   buffer_uuid,
                                   info->tmp_buffer,
                                   info->tmp_buflen,
                                   &timestamp,
                                   global_volume);

        nexus_heap_free(global_heap, info->tmp_buffer);

        info->tmp_buffer = NULL;
        info->tmp_buflen = 0;

        if (err || ret) {
            log_error("ocall_buffer_put FAILED (err=%d, ret=%d)\n", err, ret);
            return -1;
        }

        __update_timestamp(buffer_uuid, timestamp, NEXUS_FREAD);

        return 0;
    }

    return -1;
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
    struct nexus_uuid * tmp_uuid  = NULL;

    struct nexus_uuid * real_uuid = uuid;

    bool modified = supernode_del_hardlink(global_supernode, uuid, &tmp_uuid);

    // delete link from supernode
    if (modified) {
        if (nexus_metadata_store(global_supernode_metadata)) {
            log_error("could not store supernode\n");
            return -1;
        }

        // if the delete operation didn't affect an on-disk links
        if (tmp_uuid == NULL) {
            return 0;
        }

        real_uuid = tmp_uuid;
    }

    buffer_layer_evict(real_uuid);

    {
        int err = -1;
        int ret = -1;

        err = ocall_buffer_del(&ret, real_uuid, global_volume);

        // XXX: what do to about err?
        (void) ret;

        if (err) {
            log_error("ocall_buffer_del FAILED\n");
            return -1;
        }
    }

    return 0;
}

int
buffer_layer_hardlink(struct nexus_uuid * src_uuid, struct nexus_uuid * dst_uuid)
{
    if (supernode_add_hardlink(global_supernode, src_uuid, dst_uuid)) {
        log_error("could not add hardlink to supernode\n");
        return -1;
    }

    if (nexus_metadata_store(global_supernode_metadata)) {
        log_error("stores the supernode\n");
        return -1;
    }

    return 0;
}

int
buffer_layer_rename(struct nexus_uuid * from_uuid, struct nexus_uuid * to_uuid)
{
    bool is_real_file = true; // we assume we are renaming a "real file"

    supernode_rename_link(global_supernode, from_uuid, to_uuid, &is_real_file);

    if (nexus_metadata_store(global_supernode_metadata)) {
        log_error("supernode_store FAILED\n");
        return -1;
    }

    if (is_real_file) {
        int ret = -1;
        int err = -1;

        err = ocall_buffer_rename(&ret, from_uuid, to_uuid, global_volume);

        if (err || ret) {
            log_error("ocall_buffer_hardlink FAILED (err=%d, ret=%d)\n", err, ret);
            return -1;
        }
    }

    return 0;
}
