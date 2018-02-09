#pragma once

#include <stdint.h>

#include <nexus_list.h>

struct nexus_acl {
    size_t count;

    struct nexus_list acls;
};

typedef enum {
    NEXUS_PERM_READ   = 0x0001,
    NEXUS_PERM_WRITE  = 0x0002,
    NEXUS_PERM_CREATE = 0x0004,
    NEXUS_PERM_DELETE = 0x0008,
    NEXUS_PERM_LOOKUP = 0x0010,
    NEXUS_PERM_ADMIN  = 0x0020
} nexus_perm_t;

typedef uint32_t nexus_uid_t;

/**
 * an ACL entry associates a user id to a permission
 */
struct nexus_acl_entry {
    nexus_perm_t perm;
    nexus_uid_t  uid;
};

/**
 * Parses a buffer containing ACL entries
 * @param buffer
 * @param buflen
 * @return nexus_acl
 */
struct nexus_acl *
nexus_acl_from_buffer(uint8_t * buffer, size_t buflen);

/**
 * Serializes the ACL unto a buffer
 * @param nexus_acl
 * @param buffer
 * @return 0 on success
 */
int
nexus_acl_to_buffer(struct nexus_acl * nexus_acl, uint8_t * buffer);

/**
 * initalizes a nexus ACL
 * @param nexus_acl
 */
void
nexus_acl_init(struct nexus_acl * nexus_acl);

/**
 * Frees resources allocated in the ACL
 * @param nexus_acl
 */
void
nexus_acl_free(struct nexus_acl * nexus_acl);

/**
 * Returns the buffer size necessary for serialization of the ACL
 * @param nexus_acl
 * @return the size
 */
size_t
nexus_acl_size(struct nexus_acl * nexus_acl);

/**
 * Adds a new ACL entry
 *
 * @param nexus_acl
 * @param uid the user's ID
 * @param rights
 *
 * @return 0 on success
 */
int
nexus_acl_set(struct nexus_acl * nexus_acl, nexus_uid_t uid, nexus_perm_t perm);

/**
 * Removes ACL entry from user
 * @param nexus_acl
 */
int
nexus_acl_unset(struct nexus_acl * nexus_acl, nexus_uid_t uid, nexus_perm_t perm);

/**
 * Removes a user's entry from the ACL, effectively unsetting all rights
 * @param nexus_acl
 * @param uid
 */
int
nexus_acl_remove(struct nexus_acl * nexus_acl, nexus_uid_t uid);

/**
 * Checks if the currently authenticated user has the right to perform a given action
 * @param nexus_acl
 * @param perm
 * @return true on success
 */
bool
nexus_acl_check(struct nexus_acl * nexus_acl, nexus_perm_t perm);
