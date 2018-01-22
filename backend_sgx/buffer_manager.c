#include "internal.h"

#include "xxhash.h"

#include <nexus_hashtable.h>

struct __buf {
    struct nexus_uuid uuid;

    uint8_t * addr;
    size_t    size;
};

// XXX given that uuid's are random, not sure if having a prime number for capacity
// buys us much
#define BUFFER_TABLE_SIZE 127

static struct nexus_hashtable * buffer_table = NULL;

static size_t buffer_table_size = 0;


static uint32_t
hash_func(uintptr_t key)
{
    struct nexus_uuid * uuid = (struct nexus_uuid *)key;

    return (uint32_t)(XXH32(uuid, sizeof(struct nexus_uuid), 0));
}

static int
equal_func(uintptr_t key1, uintptr_t key2)
{
    return nexus_uuid_compare((struct nexus_uuid *)key1, (struct nexus_uuid *)key2);
}

int
buffer_manager_init()
{
    buffer_table = nexus_create_htable(BUFFER_TABLE_SIZE, hash_func, equal_func);

    if (buffer_table == NULL) {
        log_error("nexus_create_htable FAILED\n");
        return -1;
    }

    return 0;
}

void
buffer_manager_exit()
{
    // only free the values
    nexus_free_htable(buffer_table, 1, 0);
}

struct nexus_uuid *
__alloc_buf(uint8_t * addr, size_t size)
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

        ret = nexus_htable_insert(buffer_table, (uintptr_t)uuid, (uintptr_t)buf);
        if (ret) {
            log_error("nexus_htable_insert FAILED\n");
            goto cleanup;
        }
    }

    buffer_table_size += 1;

    return uuid;
cleanup:
    nexus_free(buf);

    return NULL;
}

uint8_t *
buffer_manager_alloc(size_t size, struct nexus_uuid * dest_uuid)
{
    uint8_t * addr = NULL;

    struct nexus_uuid * uuid = NULL;


    addr = nexus_malloc(size);

    uuid = __alloc_buf(addr, size);
    if (uuid == NULL) {
        goto cleanup;
    }

    // copy out the uuid
    nexus_uuid_copy(uuid, dest_uuid);
cleanup:
    nexus_free(addr);

    return NULL;
}

struct nexus_uuid *
buffer_manager_create(uint8_t * addr, size_t size)
{
    struct nexus_uuid * uuid = NULL;

    uuid = __alloc_buf(addr, size);
    if (uuid) {
        return nexus_uuid_clone(uuid);
    }

    return NULL;
}

uint8_t *
buffer_manager_get(struct nexus_uuid * uuid, size_t * p_buffer_size)
{
    struct __buf * buf = NULL;

    buf = nexus_htable_search(buffer_table, (uintptr_t)uuid);
    if (buf == NULL) {
        return NULL;
    }

    *p_buffer_size = buf->size;

    return buf->addr;
}

void
buffer_manager_free(struct nexus_uuid * uuid)
{
    struct __buf * buf = NULL;

    buf = (struct __buf *)nexus_htable_remove(buffer_table, (uintptr_t)uuid, 0);
    if (buf == NULL) {
        return;
    }

    buffer_table_size -= 1;
    nexus_free(buf);
}
