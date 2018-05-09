#include "enclave_internal.h"


struct __timestamp {
    struct nexus_uuid uuid;
    size_t            timestamp;
};


struct nexus_hashtable * timestamp_htable = NULL;


int
buffer_layer_init()
{
    timestamp_htable = nexus_create_htable(127, __uuid_hasher, __uuid_equals);

    return 0;
}

int
buffer_layer_exit()
{
    nexus_free_htable(timestamp_htable, 1, 0);
    return 0;
}

static void
__update_timestamp(struct nexus_uuid * uuid, size_t timestamp)
{
    struct __timestamp * tstamp = NULL;

    tstamp = (struct __timestamp *)nexus_htable_search(timestamp_htable, (uintptr_t)uuid);

    if (tstamp == NULL) {
        tstamp =  nexus_malloc(sizeof(struct __timestamp));

        tstamp->timestamp = timestamp;
        nexus_uuid_copy(uuid, &tstamp->uuid);

        nexus_htable_insert(timestamp_htable, (uintptr_t)&tstamp->uuid, (uintptr_t)tstamp);

        return;
    }

    tstamp->timestamp = timestamp;
}

static void
__remove_timestamp(struct nexus_uuid * uuid)
{
    struct __timestamp * tstamp = NULL;

    tstamp = (struct __timestamp *)nexus_htable_remove(timestamp_htable, (uintptr_t)uuid, 0);

    nexus_free(tstamp);
}

int
buffer_layer_revalidate(struct nexus_uuid * uuid, bool * should_reload)
{
    struct __timestamp * tstamp    = NULL;

    size_t stat_timestamp;

    int err = -1;
    int ret = -1;

    // check if we have a timestamp
    tstamp = (struct __timestamp *)nexus_htable_search(timestamp_htable, (uintptr_t)uuid);

    if (tstamp == NULL) {
        *should_reload = true;
        return 0;
    }

    err = ocall_buffer_stattime(&ret, uuid, &stat_timestamp, global_volume);

    if (err || ret) {
        log_error("ocall_buffer_stat FAILED (err=%d, ret=%d)\n", err, ret);
        return -1;
    }

    *should_reload = stat_timestamp > tstamp->timestamp;

    return 0;
}

uint8_t *
buffer_layer_alloc(struct nexus_uuid * uuid, size_t size)
{
    int       err  = -1;
    uint8_t * addr = NULL;

    err = ocall_buffer_alloc(&addr, uuid, size, global_volume);

    if (err || addr == NULL) {
        log_error("ocall_buffer_alloc FAILED (err=%d)\n", err);
        return NULL;
    }

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

    __update_timestamp(uuid, timestamp);

    return external_addr;
}

int
buffer_layer_put(struct nexus_uuid * buffer_uuid)
{
    size_t timestamp = 0;

    int err = -1;
    int ret = -1;

    err = ocall_buffer_put(&ret, buffer_uuid, &timestamp, global_volume);

    if (err || ret) {
        log_error("ocall_buffer_put FAILED (err=%d, ret=%d)\n", err, ret);
        return -1;
    }

    __update_timestamp(buffer_uuid, timestamp);

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

    __remove_timestamp(real_uuid);

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
