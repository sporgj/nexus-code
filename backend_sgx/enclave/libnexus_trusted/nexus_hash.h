#pragma once

// sha256
#define CONFIG_HASH_SIZE 32

struct nexus_hash {
    uint8_t bytes[CONFIG_HASH_SIZE];
};

void
nexus_hash_gen(struct nexus_hash * hash, void * buffer, size_t buflen);

struct nexus_hash *
nexus_hash_compute(void * buffer, size_t buflen);

/**
 * returns if hash1 and hash2 are equal
 */
int
nexus_hash_equals(struct nexus_hash * hash1, struct nexus_hash * hash2);

void
nexus_hash_copy(struct nexus_hash * src_hash, struct nexus_hash * dst_hash);

struct nexus_hash *
nexus_hash_clone(struct nexus_hash * hash);
