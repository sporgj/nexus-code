#pragma once

#include <stdint.h>

#include <nexus_hash.h>
#include <nexus_list.h>


#define NEXUS_MAX_NAMELEN     25

#define NEXUS_ROOT_USER       0



typedef uint64_t              nexus_uid_t;

typedef struct nexus_hash     pubkey_hash_t;

typedef uint32_t              nexus_user_flags_t;


struct nexus_user {
    char                    * name;

    nexus_user_flags_t        flags;

    nexus_uid_t               user_id;

    pubkey_hash_t             pubkey_hash;
};

struct nexus_usertable {
    uint32_t          version;

    uint64_t          auto_increment;
    uint64_t          user_count;
    uint64_t          total_size;

    struct nexus_uuid my_uuid;

    struct nexus_user owner;

    struct nexus_list userlist;
};

/**
 * Allocates a usertable.
 *
 * @param supernode_uuid
 * @return a nexus_usertable
 */
struct nexus_usertable *
nexus_usertable_create(char * user_pubkey);

/**
 * Frees an allocated usertable
 *
 * @param usertable
 */
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

int
nexus_usertable_store(struct nexus_usertable * usertable, struct nexus_mac * mac);

/**
 * Returns user information
 * @param name
 * @return NULL if not found
 */
struct nexus_user *
nexus_usertable_find_name(struct nexus_usertable * usertable, char * name);

/**
 * Finds a pubkey in user table
 * @param usertable
 * @param pubkey
 * @return nexus_user
 */
struct nexus_user *
nexus_usertable_find_pubkey(struct nexus_usertable * usertable, pubkey_hash_t * pubkey);

/**
 * Adds a user to the usertable
 */
int
nexus_usertable_add(struct nexus_usertable * usertable, char * name, char * pubkey_str);
