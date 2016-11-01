#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "third/sds.h"

#include "uc_types.h"

struct filebox;
typedef struct filebox uc_filebox_t;

/**
 * Creates a new filebox with a default segments
 * @return NULL if we run out of memory
 */
uc_filebox_t *
filebox_new();

/**
 * Initialize a new filebox from the specified path
 * @param file_path is the absolute path to the filebox file
 * @return NULL if the filebox could not be initialized
 */
uc_filebox_t *
filebox_from_file(const sds file_path);

/**
 * Creates a filebox from an existing one
 * @param fbox is the filebox to copy from
 * @return a new filebox
 */
uc_filebox_t *
filebox_copy(const uc_filebox_t * fb);

int
filebox_equals(const uc_filebox_t * fb1, uc_filebox_t * fb2);

/**
 * Deallocates the filebox from the heap
 * @param fb
 */
void
filebox_free(uc_filebox_t * fb);

/**
 * Serializes the filebox object to disk
 * @param fb is the filebox
 * @param path is the path to filebox to save
 * @return true if operation was successful
 */
bool
filebox_write(uc_filebox_t * fb, const char * path);

/**
 * Writes the filebox to the file specified in filebox_from_file()
 * @return true if the operation was successful
 */
bool
filebox_flush(uc_filebox_t * fb);

int filebox_decr_link_count(uc_filebox_t * fb);

int filebox_incr_link_count(uc_filebox_t * fb);

/**
 * Returns the crypto context at the specific chunk id
 * @param chunk_id
 * @return NULL if the id is invalid
 */
crypto_context_t *
filebox_get_crypto(uc_filebox_t * fb, size_t chunk_id);

/**
 * Updates the crypto context at the specified chunk id
 * @param fb
 * @param chunk_id
 * @param crypto_ctx
 */
void
filebox_set_crypto(uc_filebox_t * fb,
                   size_t chunk_id,
                   crypto_context_t * crypto_ctx);

#ifdef __cplusplus
}
#endif
