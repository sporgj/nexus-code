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
    struct nexus_hashtable * buffers_table;

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

    buf_manager->buffers_table = nexus_create_htable(BUFFER_TABLE_SIZE, hash_func, equal_func);

    if (buf_manager->buffers_table == NULL) {
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
    nexus_free_htable(buf_manager->buffers_table, 1, 0);
    nexus_free(buf_manager);
}

int
__alloc_buf(struct buffer_manager * buf_manager,
            uint8_t               * addr,
            size_t                  size,
            struct nexus_uuid     * uuid)
{
    struct __buf * buf = NULL;


    buf = nexus_malloc(sizeof(struct __buf));

    buf->addr = addr;
    buf->size = size;

    buf->refcount = 1;

    nexus_uuid_copy(uuid, &buf->uuid);

    // insert in the htable
    {
        struct __buf * old_buf = NULL;
        int ret = -1;

        // XXX, for now, we remove the old and add the new
        old_buf = (struct __buf *)nexus_htable_remove(buf_manager->buffers_table, (uintptr_t)&buf->uuid, 0);
        if (old_buf) {
            nexus_free(old_buf);
        }

        ret = nexus_htable_insert(buf_manager->buffers_table, (uintptr_t)&buf->uuid, (uintptr_t)buf);
        if (ret == 0) {
            log_error("nexus_htable_insert FAILED\n");
            goto cleanup;
        }
    }

    buf_manager->table_size += 1;

    return 0;
cleanup:
    nexus_free(buf);

    return -1;
}

uint8_t *
buffer_manager_alloc(struct buffer_manager * buf_manager, size_t size, struct nexus_uuid * buf_uuid)
{
    uint8_t * addr = NULL;

    int ret = -1;

    addr = nexus_malloc(size);

    // TODO invalidate existing entry

    ret = __alloc_buf(buf_manager, addr, size, buf_uuid);
    if (ret != 0) {
        goto cleanup;
    }

    return addr;
cleanup:
    nexus_free(addr);

    return NULL;
}


int
buffer_manager_add(struct buffer_manager * buf_manager, uint8_t * addr, size_t size, struct nexus_uuid * uuid)
{
    return __alloc_buf(buf_manager, addr, size, uuid);
}


uint8_t *
buffer_manager_get(struct buffer_manager * buf_manager,
                   struct nexus_uuid     * uuid,
                   size_t                * p_buffer_size)
{
    struct __buf * buf = NULL;

    buf = nexus_htable_search(buf_manager->buffers_table, (uintptr_t)uuid);
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

    buf = (struct __buf *)nexus_htable_cond_remove(buf_manager->buffers_table,
                                                   (uintptr_t)uuid,
                                                   0,
                                                   conditional_remove_func);

    if (buf == NULL) {
        return;
    }

    nexus_free(buf);
}

void
buffer_manager_del(struct buffer_manager * buf_manager, struct nexus_uuid * uuid)
{
    struct __buf * buf = NULL;

    buf = (struct __buf *)nexus_htable_remove(buf_manager->buffers_table, (uintptr_t)uuid, 0);

    if (buf == NULL) {
        return;
    }

    nexus_free(buf);
}
