#include "internal.h"

#include <time.h>

#include <nexus_hashtable.h>

#define HASHTABLE_SIZE 127

struct buffer_manager {
    struct nexus_hashtable * buffers_table;

    size_t                   table_size;

    // TODO it may be helpful to have the total size occupied by the buffers
};


void
free_buf(struct metadata_buf * buf)
{
    nexus_free(buf->addr);
    nexus_free(buf);
}

struct buffer_manager *
buffer_manager_init()
{
    struct buffer_manager * buf_manager = nexus_malloc(sizeof(struct buffer_manager));

    buf_manager->buffers_table = nexus_create_htable(HASHTABLE_SIZE,
                                                     uuid_hash_func,
                                                     uuid_equal_func);

    if (buf_manager->buffers_table == NULL) {
        nexus_free(buf_manager);
        log_error("nexus_create_htable FAILED\n");
        return NULL;
    }

    return buf_manager;
}

void
buffer_manager_destroy(struct buffer_manager * buf_manager)
{
    // TODO: free buf->addr
    // only free the values
    nexus_free_htable(buf_manager->buffers_table, 1, 0);
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
        free_buf(old_buf);

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

    free_buf(buf);
}
