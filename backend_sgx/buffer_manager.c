#include "internal.h"

#include <time.h>

#include <nexus_hashtable.h>

#define HASHTABLE_SIZE 127

struct buffer_manager {
    struct nexus_hashtable * buffers_table;

    size_t                   table_size;

    // TODO it may be helpful to have the total size occupied by the buffers
};


static bool
conditional_remove_func(uintptr_t value)
{
    struct metadata_buf * buf = (struct metadata_buf *)value;

    buf->refcount -= 1;

    if (buf->refcount < 0) {
        // XXX
        log_error("refcount on buffer is < 0\n");
        return false;
    }

    return buf->refcount == 0;
}

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

static struct metadata_buf *
__alloc_buf(struct buffer_manager * buf_manager,
            uint8_t               * addr,
            size_t                  size,
            struct nexus_uuid     * uuid,
            bool                    on_disk)
{
    struct metadata_buf       * buf         = NULL;

    struct nexus_file_handle  * locked_file = NULL;

    buf = nexus_malloc(sizeof(struct metadata_buf));

    buf->addr                 = addr;
    buf->size                 = size;

    buf->refcount             = 1;
    buf->on_disk              = on_disk;

    buf->timestamp            = time(NULL);

    nexus_uuid_copy(uuid, &buf->uuid);

    // insert in the htable
    {
        struct metadata_buf * old_buf = NULL;

        uintptr_t      key            = (uintptr_t)&buf->uuid;

        int            ret            = -1;

        // XXX, for now, we remove the old and add the new.
        old_buf = (struct metadata_buf *)nexus_htable_remove(buf_manager->buffers_table, key, 0);

        if (old_buf) {
            locked_file = old_buf->locked_file;

            free_buf(old_buf);
            buf_manager->table_size -= 1;
        }

        ret = nexus_htable_insert(buf_manager->buffers_table, key, (uintptr_t)buf);

        if (ret == 0) {
            log_error("nexus_htable_insert FAILED\n");
            goto cleanup;
        }
    }

    buf->locked_file = locked_file;

    buf_manager->table_size += 1;

    return buf;
cleanup:
    nexus_free(buf);

    return NULL;
}

struct metadata_buf *
__buffer_manager_alloc(struct buffer_manager * buf_manager, size_t size, struct nexus_uuid * buf_uuid)
{
    uint8_t             * addr = nexus_malloc(size);

    struct metadata_buf * buf  = __alloc_buf(buf_manager, addr, size, buf_uuid, false);

    if (buf == NULL) {
        nexus_free(addr);
        return NULL;
    }

    return buf;
}

uint8_t *
buffer_manager_alloc(struct buffer_manager * buf_manager, size_t size, struct nexus_uuid * buf_uuid)
{
    uint8_t * addr = nexus_malloc(size);

    // FIXME. At this point, allocating a buffer (usually for writing) erases any cached read data.
    // a better solution is to associate each buf with a "write buffer".
    if (__alloc_buf(buf_manager, addr, size, buf_uuid, false) == NULL) {
        nexus_free(addr);
        return NULL;
    }

    return addr;
}

struct metadata_buf *
__buffer_manager_add(struct buffer_manager * buf_manager,
                     uint8_t               * addr,
                     size_t                  size,
                     struct nexus_uuid     * uuid)
{
    return __alloc_buf(buf_manager, addr, size, uuid, true);
}

int
buffer_manager_add(struct buffer_manager   * buf_manager,
                   uint8_t                 * addr,
                   size_t                    size,
                   struct nexus_uuid       * uuid)
{
    if (__alloc_buf(buf_manager, addr, size, uuid, true) == NULL) {
        return -1;
    }

    return 0;
}

struct metadata_buf *
buffer_manager_get(struct buffer_manager * buf_manager, struct nexus_uuid * uuid)
{
    struct metadata_buf * buf = NULL;

    buf = nexus_htable_search(buf_manager->buffers_table, (uintptr_t)uuid);

    if (buf == NULL) {
        return NULL;
    }

    buf->refcount += 1;

    return buf;
}

struct metadata_buf *
buffer_manager_find(struct buffer_manager * buf_manager, struct nexus_uuid * uuid)
{
    return nexus_htable_search(buf_manager->buffers_table, (uintptr_t)uuid);
}

void
buffer_manager_put(struct buffer_manager * buf_manager, struct nexus_uuid * uuid)
{
    struct metadata_buf * buf = NULL;

    buf = (struct metadata_buf *)nexus_htable_cond_remove(buf_manager->buffers_table,
                                                   (uintptr_t)uuid,
                                                   0,
                                                   conditional_remove_func);

    if (buf == NULL) {
        return;
    }

    free_buf(buf);
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
