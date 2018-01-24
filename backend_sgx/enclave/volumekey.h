#pragma once
/**
 * Each enclave will have a single global volumekey
 */

#include "nexus_key.h"
#include "sealed_buffer.h"

/**
 * Generates a new enclave volumekey
 * @return 0 on success
 */
int
enclave_volumekey_gen();

/**
 * Clears the enclave volumekey
 */
void
enclave_volumekey_clear();

/**
 * Returns a sealed_buffer of the volumekey
 * @return NULL on failure
 */
struct nexus_sealed_buf *
enclave_volumekey_serialize();


/**
 * parses a volumekey
 * @param sealed_buf
 * @return 0 on success
 */
int
enclave_volumekey_init(struct nexus_sealed_buf * sealed_buf);
