#include <stdlib.h>
#include <string.h>

#include <sgx_trts.h>
#include <sgx_tseal.h>
#include <sgx_utils.h>

#include <mbedtls/pk.h>

#include "nx_enclave_t.h"

extern sgx_key_128bit_t enclave_sealing_key;

int
supernode_encrypt_and_seal(struct supernode * supernode,
                           crypto_ekey_t *    rootkey);

int
dirnode_encrypt_and_seal(struct dirnode * dirnode, crypto_ekey_t * rootkey);

/**
 * Protects the rootkey with the enclave sealing key before it is sent to
 * untrusted memory.
 */
int
volume_rootkey_wrap(crypto_ekey_t * rootkey);

int
volume_rootkey_unwrap(crypto_ekey_t * rootkey);
