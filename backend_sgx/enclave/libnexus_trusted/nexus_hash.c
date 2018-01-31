#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "nexus_hash.h"
#include "nexus_util.h"

#include <mbedtls/sha256.h>


void
nexus_hash_clear(struct nexus_hash * hash)
{
    memset(hash, 0, sizeof(struct nexus_hash));
}

void
nexus_hash_generate(struct nexus_hash * hash, void * buffer, size_t buflen)
{
    mbedtls_sha256(buffer, buflen, (uint8_t *)&hash->bytes, 0);
}

struct nexus_hash *
nexus_hash_compute(void * buffer, size_t buflen)
{
    struct nexus_hash * hash = nexus_malloc(sizeof(struct nexus_hash));

    nexus_hash_generate(hash, buffer, buflen);

    return hash;
}

int
nexus_hash_compare(struct nexus_hash * hash1, struct nexus_hash * hash2)
{
    return memcmp(hash1, hash2, sizeof(struct nexus_hash));
}

void
nexus_hash_copy(struct nexus_hash * src_hash, struct nexus_hash * dst_hash)
{
    memcpy(dst_hash, src_hash, sizeof(struct nexus_hash));
}

struct nexus_hash *
nexus_hash_clone(struct nexus_hash * hash)
{
    struct nexus_hash * hash_copy = nexus_malloc(sizeof(struct nexus_hash));

    nexus_hash_copy(hash, hash_copy);

    return hash_copy;
}
