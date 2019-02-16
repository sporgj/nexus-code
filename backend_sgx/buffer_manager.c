#include "internal.h"

#include <time.h>
#include <pthread.h>

#include <nexus_hashtable.h>




static int
uuid_equal_func(uintptr_t key1, uintptr_t key2)
{
    return (nexus_uuid_compare((struct nexus_uuid *)key1, (struct nexus_uuid *)key2) == 0);
}

static uint32_t
uuid_hash_func(uintptr_t key)
{
    return nexus_uuid_hash((struct nexus_uuid *)key);
}


struct buffer_manager *
buffer_manager_init()
{
    struct buffer_manager * buf_manager = nexus_malloc(sizeof(struct buffer_manager));

    buf_manager->buffers_table = nexus_create_htable(128,
                                                     uuid_hash_func,
                                                     uuid_equal_func);

    if (buf_manager->buffers_table == NULL) {
        nexus_free(buf_manager);
        log_error("nexus_create_htable FAILED\n");
        return NULL;
    }

    pthread_mutex_init(&buf_manager->batch_mutex, NULL);

    return buf_manager;
}

void
buffer_manager_destroy(struct buffer_manager * buf_manager)
{
    struct nexus_hashtable_iter * iter = nexus_htable_create_iter(buf_manager->buffers_table);

    if (iter->entry) {
        struct metadata_buf * metadata_buf = NULL;

        do {
            metadata_buf = (struct metadata_buf *)nexus_htable_get_iter_value(iter);

            __free_metadata_buf(metadata_buf);
        } while(nexus_htable_iter_advance(iter));
    }

    nexus_htable_free_iter(iter);

    // only frees the table
    nexus_free_htable(buf_manager->buffers_table, 0, 0);

    pthread_mutex_destroy(&buf_manager->batch_mutex);

    nexus_free(buf_manager);
}

void
buffer_manager_add(struct buffer_manager * buf_manager, struct metadata_buf * buf)
{
    struct metadata_buf * old_buf = NULL;

    uintptr_t      key            = (uintptr_t)&buf->uuid;

    // XXX, for now, we remove the old and add the new.
    old_buf = (struct metadata_buf *)nexus_htable_remove(buf_manager->buffers_table, key, 0);

    if (old_buf) {
        __free_metadata_buf(old_buf);

        buf_manager->table_size -= 1;
    }

    nexus_htable_insert(buf_manager->buffers_table, key, (uintptr_t)buf);

    buf_manager->table_size += 1;
}

struct metadata_buf *
buffer_manager_find(struct buffer_manager * buf_manager, struct nexus_uuid * uuid)
{
    return nexus_htable_search(buf_manager->buffers_table, (uintptr_t)uuid);
}

void
buffer_manager_del(struct buffer_manager * buf_manager, struct nexus_uuid * uuid)
{
    struct metadata_buf * buf = NULL;

    buf = (struct metadata_buf *)nexus_htable_remove(buf_manager->buffers_table,
                                                     (uintptr_t)uuid,
                                                     0);

    if (buf == NULL) {
        return;
    }

    __free_metadata_buf(buf);
}



// I/O commands

int
buffer_manager_enable_batch_mode(struct sgx_backend * backend)
{
    pthread_mutex_lock(&backend->buf_manager->batch_mutex);
    backend->buf_manager->batch_mode = true;
    pthread_mutex_unlock(&backend->buf_manager->batch_mutex);

    return 0;
}

int
buffer_manager_disable_batch_mode(struct sgx_backend * backend)
{
    backend->buf_manager->batch_mode = false;

    return 0;
}
