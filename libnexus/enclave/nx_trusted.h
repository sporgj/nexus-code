#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <sgx_trts.h>
#include <sgx_tseal.h>
#include <sgx_utils.h>

#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>
#include <mbedtls/gcm.h>
#include <mbedtls/aes.h>

#include "queue.h"

#include "nx_enclave_t.h"

#define ocall_debug(str)                                                       \
    ocall_print("enclave> " str "\n")

#define my_free(x)                                                             \
    do {                                                                       \
        if (x != NULL) {                                                       \
            free(x);                                                           \
            x = NULL;                                                          \
        }                                                                      \
    } while (0)

extern sgx_key_128bit_t enclave_sealing_key;

struct dirnode_list_entry {
    TAILQ_ENTRY(dirnode_list_entry) next_entry;
    struct dirnode_entry * data_ptr;
};

struct dirnode_wrapper {
    size_t current_tsize;
    size_t current_dircount;
    struct dirnode * dirnode;
    TAILQ_HEAD(dirnode_list_entry_head, dirnode_list_entry) entries_list;
};

int
supernode_encryption1(struct supernode *  supernode,
                      struct volumekey *  volumekey,
                      struct supernode ** p_sealed_supernode);

int
supernode_decryption1(struct supernode *  sealed_supernode,
                      struct volumekey *  volumekey,
                      struct supernode ** p_supernode);

int
dirnode_encryption1(struct dirnode *   dirnode,
                    struct volumekey * volkey,
                    struct dirnode **  sealed_dirnode);
/**
 * Calls dirnode_encrypt_and_seal() after using the dirnode uuid to find
 * the volume key.  */
int
dirnode_encryption(struct dirnode *  dirnode,
                   struct dirnode ** p_sealed_dirnode);

int
dirnode_decryption(struct dirnode *  sealed_dirnode,
                   struct dirnode ** p_dirnode);

/**
 * Protects the volkey with the enclave sealing key before it is sent to
 * untrusted memory.
 */
int
volumekey_wrap(struct volumekey * volkey);

int
volumekey_unwrap(struct volumekey * volkey);

struct volumekey *
volumekey_from_rootuuid(struct uuid * root_uuid);

/* dirnode */

/**
 * Creates a new dirnode
 * @param uuid
 * @param root_uuid
 * @return NULL on FAILURE
 */
struct dirnode *
dirnode_new(struct uuid * uuid, struct uuid * root_uuid);

/**
 * Creates/Loads a new dirnode wrapper from a dirnode object.
 * @param dirnode
 * @return NULL
 */
struct dirnode_wrapper *
dirnode_load(struct dirnode * dirnode);
