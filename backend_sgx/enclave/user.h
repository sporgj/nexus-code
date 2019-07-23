#pragma once

#include <stdint.h>

#include <nexus_hash.h>
#include <nexus_list.h>

#include "crypto.h"

#ifndef NEXUS_MAX_NAMELEN
#define NEXUS_MAX_NAMELEN         25
#endif

#define NEXUS_ROOT_USER           0

#define NEXUS_INVALID_USER_ID     UINT64_MAX


struct nexus_supernode;

typedef uint64_t              nexus_uid_t;

typedef uint32_t              nexus_user_flags_t;


struct nexus_user {
    char                    * name;

    nexus_user_flags_t        flags;

    nexus_uid_t               user_id;

    struct nexus_uuid         user_uuid;

    pubkey_hash_t             pubkey_hash;
};

struct nexus_usertable {
    uint64_t          auto_increment;
    uint64_t          user_count;
    uint64_t          total_size;

    struct nexus_uuid my_uuid;
    struct nexus_uuid root_uuid;

    struct nexus_user owner;

    struct nexus_list userlist;

    struct nexus_mac  mac;

    struct nexus_metadata * metadata;
};


void
__usertable_set_supernode(struct nexus_usertable * usertable, struct nexus_supernode * supernode);

void
nexus_usertable_set_owner_pubkey(struct nexus_usertable * usertable, char * user_pubkey);

struct nexus_usertable *
nexus_usertable_create(struct nexus_uuid * root_uuid, struct nexus_uuid * uuid);

void
nexus_usertable_free(struct nexus_usertable * usertable);

void
nexus_usertable_copy_uuid(struct nexus_usertable * usertable, struct nexus_uuid * dest_uuid);

/**
 * Parses usertable from a buffer
 *
 * @param buffer
 * @param buflen
 * @return usertable
 */
struct nexus_usertable *
nexus_usertable_load(struct nexus_uuid * uuid, nexus_io_flags_t flags, struct nexus_mac * mac);

struct nexus_usertable *
nexus_usertable_from_crypto_buf(struct nexus_crypto_buf * crypto_buffer);

int
nexus_usertable_store(struct nexus_usertable * usertable, uint32_t version, struct nexus_mac * mac);

struct nexus_list_iterator *
__nexus_usertable_get_iterator(struct nexus_usertable * usertable);

/**
 * Returns user information
 * @param name
 * @return NULL if not found
 */
struct nexus_user *
nexus_usertable_find_name(struct nexus_usertable * usertable, char * name);

struct nexus_user *
nexus_usertable_find_uuid(struct nexus_usertable * usertable, struct nexus_uuid * uuid);

struct nexus_user *
nexus_usertable_find_pubkey_hash(struct nexus_usertable * usertable, pubkey_hash_t * pubkey_hash);

/**
 * Finds a pubkey in user table
 * @param usertable
 * @param pubkey
 * @return nexus_user
 */
struct nexus_user *
nexus_usertable_find_pubkey(struct nexus_usertable * usertable, char * pubkey_str);

/**
 * Adds a user to the usertable
 */
int
nexus_usertable_add(struct nexus_usertable * usertable, char * name, char * pubkey_str);

struct nexus_user *
__nexus_usertable_add(struct nexus_usertable * usertable, char * name, char * pubkey_str);

int
nexus_usertable_remove_username(struct nexus_usertable * usertable,
                                char                   * username,
                                struct nexus_uuid      * uuid);

int
nexus_usertable_remove_pubkey(struct nexus_usertable * usertable,
                              char                   * pubkey_str,
                              struct nexus_uuid      * uuid);
