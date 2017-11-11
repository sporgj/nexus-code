#include <stdlib.h>
#include <string.h>

#include <sgx_trts.h>
#include <sgx_tseal.h>
#include <sgx_utils.h>

#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>

#include "nx_enclave_t.h"

#define ocall_debug(str) ocall_print("enclave> %s(%d): " str "\n")

#define my_free(x)                                                             \
    do {                                                                       \
        if (x != NULL) {                                                       \
            free(x);                                                           \
            x = NULL;                                                          \
        }                                                                      \
    } while (0)

extern sgx_key_128bit_t enclave_sealing_key;

int
supernode_encrypt_and_seal(struct supernode  * supernode,
                           struct volumekey * volkey);

int
supernode_decrypt_and_unseal(struct supernode *  supernode,
                             struct volumekey * volkey);

int
dirnode_encrypt_and_seal(struct dirnode * dirnode, struct volumekey * volkey);

int
dirnode_decrypt_and_unseal(struct dirnode *    dirnode,
                           struct volumekey * volkey);

/**
 * Protects the volkey with the enclave sealing key before it is sent to
 * untrusted memory.
 */
int
volumekey_wrap(struct volumekey * volkey);

int
volumekey_unwrap(struct volumekey * volkey);
