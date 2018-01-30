#include "internal.h"

#include "xxhash.h"

#include <nexus_hashtable.h>

struct __buf {
    struct nexus_uuid uuid;

    int refcount; // TODO consider switching to atomic.h

    uint8_t * addr;
    size_t    size;
};

// XXX given that uuid's are random, not sure if having a prime number for capacity
// buys us much
#define BUFFER_TABLE_SIZE 127

struct buffer_manager {
    struct nexus_hashtable * buffer_table;

    size_t                   table_size;

    // TODO it may be helpful to have the total size occupied by the buffers
};


static uint32_t
hash_func(uintptr_t key)
{
    struct nexus_uuid * uuid = (struct nexus_uuid *)key;

    return (uint32_t)(XXH32(uuid, sizeof(struct nexus_uuid), 0));
}

static int
equal_func(uintptr_t key1, uintptr_t key2)
{
    return nexus_uuid_compare((struct nexus_uuid *)key1, (struct nexus_uuid *)key2) == 0;
}

static bool
conditional_remove_func(uintptr_t value)
{
    struct __buf * buf = (struct __buf *)value;

    buf->refcount -= 1;

    if (buf->refcount < 0) {
        // XXX
        log_error("refcount on buffer is < 0\n");
        return false;
    }

    return buf->refcount == 0;
}

struct buffer_manager *
new_buffer_manager()
{
    struct buffer_manager * buf_manager = NULL;

    buf_manager = nexus_malloc(sizeof(struct buffer_manager));

    buf_manager->buffer_table = nexus_create_htable(BUFFER_TABLE_SIZE, hash_func, equal_func);

    if (buf_manager->buffer_table == NULL) {
        nexus_free(buf_manager);
        log_error("nexus_create_htable FAILED\n");
        return NULL;
    }

    return buf_manager;
}

void
free_buffer_manager(struct buffer_manager * buf_manager)
{
    // only free the values
    nexus_free_htable(buf_manager->buffer_table, 1, 0);
    nexus_free(buf_manager);
}

struct nexus_uuid *
__alloc_buf(struct buffer_manager * buf_manager, uint8_t * addr, size_t size)
{
    struct __buf * buf = NULL;

    struct nexus_uuid * uuid = NULL;


    buf = nexus_malloc(sizeof(struct __buf));

    buf->addr = addr;
    buf->size = size;

    uuid = &buf->uuid;
    nexus_uuid_gen(uuid);

    // insert in the htable
    {
        int ret = -1;

        // XXX jbd: the hashtable has no guarantees for duplicate keys
        // assuming the UUIDs are unique, we _shouldn't_ have any issues

        ret = nexus_htable_insert(buf_manager->buffer_table, (uintptr_t)uuid, (uintptr_t)buf);
        if (ret == 0) {
            log_error("nexus_htable_insert FAILED\n");
            goto cleanup;
        }
    }

    buf->refcount = 1;

    buf_manager->table_size += 1;

    return uuid;
cleanup:
    nexus_free(buf);

    return NULL;
}

uint8_t *
buffer_manager_alloc(struct buffer_manager * buf_manager,
                     size_t                  size,
                     struct nexus_uuid     * dest_uuid)
{
    uint8_t * addr = NULL;

    struct nexus_uuid * uuid = NULL;


    addr = nexus_malloc(size);

    uuid = __alloc_buf(buf_manager, addr, size);
    if (uuid == NULL) {
        goto cleanup;
    }

    // copy out the uuid
    nexus_uuid_copy(uuid, dest_uuid);
    return addr;
cleanup:
    nexus_free(addr);

    return NULL;
}

struct nexus_uuid *
buffer_manager_add(struct buffer_manager * buf_manager, uint8_t * addr, size_t size)
{
    struct nexus_uuid * uuid = NULL;

    uuid = __alloc_buf(buf_manager, addr, size);
    if (uuid) {
        return nexus_uuid_clone(uuid);
    }

    return NULL;
}

struct nexus_uuid *
buffer_manager_add_explicit(struct buffer_manager * buf_manager, uint8_t * addr, size_t size)
{
    uint8_t * buffer_copy = NULL;

    buffer_copy = nexus_malloc(size);

    memcpy(buffer_copy, addr, size);

    return buffer_manager_add(buf_manager, buffer_copy, size);
}

uint8_t *
buffer_manager_get(struct buffer_manager * buf_manager,
                   struct nexus_uuid     * uuid,
                   size_t                * p_buffer_size)
{
    struct __buf * buf = NULL;

    buf = nexus_htable_search(buf_manager->buffer_table, (uintptr_t)uuid);
    if (buf == NULL) {
        return NULL;
    }

    buf->refcount += 1;

    *p_buffer_size = buf->size;

    return buf->addr;
}

void
buffer_manager_put(struct buffer_manager * buf_manager, struct nexus_uuid * uuid)
{
    struct __buf * buf = NULL;

    buf = (struct __buf *)nexus_htable_cond_remove(buf_manager->buffer_table,
                                                   (uintptr_t)uuid,
                                                   0,
                                                   conditional_remove_func);

    if (buf == NULL) {
        return;
    }

    buf_manager->table_size -= 1;
    nexus_free(buf);
}
