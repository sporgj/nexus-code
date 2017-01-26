#pragma once
#include <stdbool.h>

#include "uc_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Creates a new supernode. Called to initialize a new repository
 */
supernode_t * supernode_new();

/**
 * Loads a supernode object from file
 * @param path is the path to the file
 */
supernode_t * supernode_from_file(const char * path);

/**
 * Frees the resources occupied by the supernode
 */
void supernode_free(supernode_t * super);

/**
 * Writes the supernode to disk
 * @param super
 * @param path
 */
bool supernode_write(supernode_t * super, const char * path);

/**
 * When read from a file, the supernode's data is stored in a
 * buffer. However, once the supernode has been verified by SGX
 * it is now able to add/remove/list the users.
 *
 * Call this function after calling supernode_from_file success-
 * fully.
 *
 * @param super is the supernode object
 * @return 0 on success
 */
int
supernode_mount(supernode_t * super);

/**
 * Lists all the users in the supernode. Once user per line.
 * TODO provide callback argument for custom implementations.
 * @param super
 */
void supernode_list(supernode_t * super);

/**
 * Adds a new user to the supernode. [list_mode]
 * @param super
 * @param username is the username
 * @param hash is the hash of the public key
 * @return 0 on success
 */
int
supernode_add(supernode_t * super,
              const char * username,
              const uint8_t hash[CONFIG_SHA256_BUFLEN]);

/**
 * Removes user from the supernode. One could either specify
 * the username or the hash of the public key
 *
 * @param super is the supernode
 * @param username (optional) the username
 * @param hash (optional) the hash of the public key.
 */
int
supernode_rm(supernode_t * super,
             const char * username,
             const uint8_t hash[CONFIG_SHA256_BUFLEN]);

#ifdef __cplusplus
}
#endif
