#include <stdlib.h>
#include <string.h>

#include <sgx_trts.h>
#include <sgx_tseal.h>
#include <sgx_utils.h>

#include <mbedtls/pk.h>

#include "nx_enclave_t.h"

extern sgx_key_128bit_t enclave_sealing_key;

int
supernode_encrypt_and_seal(struct supernode  * supernode,
                           struct volume_key * volkey);

int
dirnode_encrypt_and_seal(struct dirnode * dirnode, struct volume_key * volkey);

/**
 * Protects the volkey with the enclave sealing key before it is sent to
 * untrusted memory.
 */
int
volume_key_wrap(struct volume_key * volkey);

int
volume_key_unwrap(struct volume_key * volkey);
