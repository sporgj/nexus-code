#pragma once

/**
 * Key buffer aids in transferring sealed cryptographic keys across the enclave
 *
 * @author Judicael Briand <jbriand@cs.pitt.edu>, 2018
 */

void
key_buffer_init(struct nexus_key_buffer * key_buffer);

int
key_buffer_put(struct nexus_key_buffer * key_buffer, struct nexus_key * key);

void
key_buffer_free(struct nexus_key_buffer * key_buffer);

int
key_buffer_derive(struct nexus_key_buffer * key_buffer, struct nexus_key * key);
