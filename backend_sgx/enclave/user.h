#pragma once

#include <stdint.h>

#define NEXUS_MAX_NAMELEN 25


typedef uint32_t nexus_uid_t;

typedef struct nexus_mac pubkey_hash_t;

typedef uint32_t nexus_user_flags_t;

struct nexus_user {
    char * name;

    nexus_user_flags_t flags;

    pubkey_hash_t pubkey;
};


struct nexus_usertable;


/**
 * Allocates a usertable.
 *
 * @param supernode_uuid
 * @return a nexus_usertable
 */
struct nexus_usertable *
nexus_usertable_create(struct nexus_uuid * supernode_uuid);

/**
 * Frees an allocated usertable
 *
 * @param usertable
 */
void
nexus_usertable_free(struct nexus_usertable * usertable);

/**
 * Parses usertable from a buffer
 *
 * @param buffer
 * @param buflen
 * @return usertable
 */
struct nexus_usertable * usertable
nexus_usertable_from_buffer(uint8_t * buffer, size_t buflen);

/**
 * Serializes the usertable to a buffer
 * @param usertable
 * @param buffer
 * @return 0 on success
 */
int
nexus_usertable_to_buffer(struct nexus_usertable * usertable, uint8_t * buffer);


/**
 * Returns user information
 * @param name
 * @return NULL if not found
 */
struct nexus_user *
nexus_usertable_get(char * name);

/**
 * Adds a user to the usertable
 */
int
nexus_usertable_add(struct nexus_usertable * usertable, char * name, char * pubkey_str);


