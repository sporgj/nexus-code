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

#include "enclave/queue.h"

/**
 * Generates a UUID in-place
 * @param uuid is the uuid object
 */
void
nexus_uuid(struct uuid * uuid);

int
read_file(const char * fpath, uint8_t ** p_buffer, size_t * p_size);

int
write_file(const char * fpath, void * buffer, size_t size);

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



char *
my_strnjoin(char * dest, const char * join, const char * src, size_t max);

char *
pathjoin(char * directory, const char * filename);

char *
my_strncat(char * dest, const char * src, size_t max);

char *
uuid_path(const char * dir_path, struct uuid * uuid);


/* used by the VFS to manage traversed paths */
struct path_element {
    struct uuid uuid;
    TAILQ_ENTRY(path_element) next_item;
};

struct path_builder {
    size_t count;  // count[path_elements]
    TAILQ_HEAD(path_list, path_element) path_head;
};

struct path_builder *
path_alloc();

int
path_push(struct path_builder * builder, struct uuid * uuid);

int
path_pop(struct path_builder * builder);

void
path_free(struct path_builder * builder);

char *
path_string(struct path_builder * builder, const char * metadata_dirpath);

#ifdef __cplusplus
}
#endif
