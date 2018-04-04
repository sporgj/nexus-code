#include "internal.h"
#include "xxhash.h"

uint32_t
uuid_hash_func(uintptr_t key)
{
    struct nexus_uuid * uuid = (struct nexus_uuid *)key;

    return (uint32_t)(XXH32(uuid, sizeof(struct nexus_uuid), 0));
}

int
uuid_equal_func(uintptr_t key1, uintptr_t key2)
{
    return nexus_uuid_compare((struct nexus_uuid *)key1, (struct nexus_uuid *)key2) == 0;
}
