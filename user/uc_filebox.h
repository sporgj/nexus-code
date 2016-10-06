#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "third/sds.h"

#include "uc_types.h"

struct filebox;

/**
 * Creates a new filebox with a default segments
 * @return NULL if we run out of memory
 */
struct filebox *
filebox_new();

/**
 * Initialize a new filebox from the specified path
 * @param file_path is the absolute path to the filebox file
 * @return NULL if the filebox could not be initialized
 */
struct filebox *
filebox_from_file(const sds file_path);

/**
 * Deallocates the filebox from the heap
 * @param fb
 */
void
filebox_free(struct filebox * fb);

/**
 * Serializes the filebox object to disk
 * @param fb is the filebox
 * @param path is the path to filebox to save
 * @return true if operation was successful
 */
bool
filebox_write(struct filebox * fb, const char * path);

/**
 * Writes the filebox to the file specified in filebox_from_file()
 * @return true if the operation was successful
 */
bool
filebox_flush(struct filebox * fb);

/**
 * Returns the crypto context at the specific chunk id
 * @param chunk_id
 * @return NULL if the id is invalid
 */
crypto_context_t *
filebox_get_crypto(struct filebox * fb, size_t chunk_id);

#ifdef __cplusplus
}
#endif
