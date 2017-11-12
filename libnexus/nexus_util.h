#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <stdint.h>

#include <mbedtls/pk.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/sha256.h>

#include "nexus.h"

/**
 * Generates a UUID in-place
 * @param uuid is the uuid object
 */
void
nexus_uuid(struct uuid * uuid);

/**
 * Reads the volume key and supernode
 * @param metadata_path
 * @param volumekey_fpath
 * @param p_supernode
 * @param p_volumekey
 */
int
read_volume_metadata_files(const char *        metadata_path,
                           const char *        volumekey_fpath,
                           struct supernode ** p_supernode,
                           struct volumekey ** p_volumekey);

/**
 * Used to initialize the enclave. Uses the objects generated
 * from nexus_create_volume(), it writes the NeXUS metadata into files
 *
 * @param supernode
 * @param root_dirnode
 * @param volumekey
 * @param metadata_path
 * @param volumekey_fpath
 */
int
write_volume_metadata_files(struct supernode * supernode,
                            struct dirnode *   root_dirnode,
                            struct volumekey * volkey,
                            const char *       metadata_path,
                            const char *       volumekey_fpath);
/**
 * Signs a blob
 * @param pk the private key
 * @param data what to sign
 * @param len length of the input data
 * @param signature destination pointer for signature
 * @param signature_len destination pointer for signature len
 */
int
util_generate_signature(mbedtls_pk_context * pk,
                        uint8_t *            data,
                        size_t               len,
                        uint8_t **           signature,
                        size_t *             signature_len);

#define nexus_free(ptr)                                                        \
    do {                                                                       \
        free(ptr);                                                             \
        ptr = NULL;                                                            \
    } while (0)

// checks pointer and then frees
#define nexus_free2(ptr)                                                       \
    do {                                                                       \
        if (ptr != NULL) {                                                     \
            nexus_free(ptr);                                                   \
        }                                                                      \
    } while (0)

char *
my_strnjoin(char * dest, const char * join, const char * src, size_t max);

char *
pathjoin(char * directory, const char * filename);

char *
my_strncat(char * dest, const char * src, size_t max);

#ifdef __cplusplus
}
#endif
