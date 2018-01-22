#include "internal.h"

#include "xxhash.h"

#include <nexus_hashtable.h>

struct __buf {
    uint8_t * addr;
    size_t    size;
};

#if 0
#define DEFAULT_TABLE_SIZE 31

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
#endif

void
buffer_manager_init()
{
    // TODO
    // create a new hashtable
}

void
buffer_manager_exit()
{
    // delete the hashtable
}

uint8_t *
buffer_manager_alloc(size_t size, struct nexus_uuid * dest_uuid)
{
    // TODO
    // create a new struct, allocate the memory
    // allocate new uuid
    // add new buffer to hashtable
    // copy out the uuid
    // return the allocated buffer address
    return NULL;
}

struct nexus_uuid *
buffer_manager_create(uint8_t * addr, size_t size)
{
    // create a new struct, setting the address and size
    // generate the uuid
    // return the uuid
    return NULL;
}

uint8_t *
buffer_manager_get(struct nexus_uuid * uuid, size_t * p_buffer_size)
{
    // perform a hashtable lookup
    // if found, return the address of the buffer
    return NULL;
}

void
buffer_manager_free(struct nexus_uuid * uuid)
{
    // do a hashtable lookup
    // free buffer
}
