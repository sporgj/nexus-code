/*
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "nexus_encode.h"

#include "../enclave_internal.h"

int
nexus_uuid_gen(struct nexus_uuid * uuid)
{
    sgx_read_rand(uuid->raw, NEXUS_UUID_SIZE);

    return 0;
}

void
nexus_uuid_zeroize(struct nexus_uuid * uuid)
{
    memset(uuid, 0, sizeof(struct nexus_uuid));
}

bool
nexus_uuid_is_zeros(struct nexus_uuid * uuid)
{
    for (size_t i = 0; i < sizeof(struct nexus_uuid); i++) {
        if (uuid->raw[i]) {
            return false;
        }
    }

    return true;
}

int
nexus_uuid_compare(struct nexus_uuid * src_uuid, struct nexus_uuid * dst_uuid)
{
    return memcmp(src_uuid, dst_uuid, sizeof(struct nexus_uuid));
}

struct nexus_uuid *
nexus_uuid_clone(struct nexus_uuid * uuid)
{
    struct nexus_uuid * new_uuid = NULL;

    new_uuid = calloc(sizeof(struct nexus_uuid), 1);

    if (new_uuid == NULL) {
        return NULL;
    }

    memcpy(new_uuid->raw, uuid->raw, NEXUS_UUID_SIZE);

    return new_uuid;
}

int
nexus_uuid_copy(struct nexus_uuid * src_uuid, struct nexus_uuid * dst_uuid)
{
    memcpy(dst_uuid->raw, src_uuid->raw, NEXUS_UUID_SIZE);

    return 0;
}

bool
nexus_uuid_is_valid(struct nexus_uuid * uuid)
{
    int i = 0;

    for (i = 0; i < NEXUS_UUID_SIZE; i++) {
        if (uuid->raw[i] != 0) {
            return true;
        }
    }

    return false;
}


/*
 * 32 bit magic FNV-0 and FNV-1 prime
 */
#define FNV_32_PRIME ((Fnv32_t)0x01000193)

/*
 * fnv_32_buf - perform a 32 bit Fowler/Noll/Vo hash on a buffer
 *
 * input:
 *      buf     - start of buffer to hash
 *      len     - length of buffer in octets
 *      hval    - previous hash value or 0 if first call
 *
 * returns:
 *  32 bit hash as a static hash type
 *
 * NOTE: To use the 32 bit FNV-0 historic hash, use FNV0_32_INIT as the hval
 *   argument on the first call to either fnv_32_buf() or fnv_32_str().
 *
 * NOTE: To use the recommended 32 bit FNV-1 hash, use FNV1_32_INIT as the hval
 *   argument on the first call to either fnv_32_buf() or fnv_32_str().
 */
// http://www.isthe.com/chongo/src/fnv/hash_32.c
uint32_t
fnv_32_buf(void * buf, size_t len, uint32_t hval)
{
    unsigned char * bp = (unsigned char *)buf; /* start of buffer */
    unsigned char * be = bp + len;             /* beyond end of buffer */

    /*
     * FNV-1 hash each octet in the buffer
     */
    while (bp < be) {

        /* multiply by the 32 bit FNV magic prime mod 2^32 */
#if defined(NO_FNV_GCC_OPTIMIZATION)
        hval *= FNV_32_PRIME;
#else
        hval += (hval << 1) + (hval << 4) + (hval << 7) + (hval << 8) + (hval << 24);
#endif

        /* xor the bottom with the current octet */
        hval ^= (uint32_t)*bp++;
    }

    /* return our new hash value */
    return hval;
}

uint32_t
nexus_uuid_hash(struct nexus_uuid * uuid)
{
    return fnv_32_buf(uuid, sizeof(struct nexus_uuid), 0);
}

char *
nexus_uuid_to_hex(struct nexus_uuid * uuid)
{
    return nexus_hex_encode((uint8_t *)uuid, sizeof(struct nexus_uuid));
}
