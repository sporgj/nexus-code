#pragma once
#include <stdbool.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "third/sds.h"

#include "uc_dirnode.h"
#include "uc_types.h"

typedef struct {
   shadow_t uuid, root;
   uint8_t chunk_size_log2; // power of 2
   uint16_t chunk_count;
   uint32_t file_size, fbox_payload_len; // the size of the chunks
   gcm_context_t gcm_crypto;
} __attribute__((packed)) filebox_header_t;

/* used for maintaining header integrity */
#define FILEBOX_HEADER_SIZE_NOCRYPTO\
   sizeof(filebox_header_t) - sizeof(gcm_context_t)

/* a chunk is just a gcm context :) */
typedef gcm_crypto_t filebox_chunk_t;

typedef struct filebox_chunk_entry {
   TAILQ_ENTRY(filebox_chunk_entry) next_entry;
   filebox_chunk_t chunk;
} filebox_chunk_entry_t;

// define the head of the list
typedef TAILQ_HEAD(chunk_list, filebox_chunk_entry) filebox_chunk_head_t;

typedef struct {
   filebox_header_t header;
   filebox_chunk_head_t chunk_list;
   filebox_chunk_entry_t * chunk0;
   sds fbox_path;
   int allocated;
   uint8_t * payload;
   bool is_ondisk; /* if the filebox has content on disk */
} uc_filebox_t;

/**
 * Creates a new filebox with a default segments
 * @return NULL if we run out of memory
 */
uc_filebox_t *
filebox_new();

uc_filebox_t *
filebox_new2(const shadow_t * id, uc_dirnode_t * dirnode);

void
filebox_set_size(uc_filebox_t * filebox, size_t size);

static inline void
filebox_set_path(uc_filebox_t * filebox, const char * path)
{
    if (filebox->fbox_path) {
        sdsfree(filebox->fbox_path);
    }

    filebox->fbox_path = sdsnew(path);
}

static inline sds
filebox_get_path(uc_filebox_t * filebox)
{
    return filebox->fbox_path ? sdsnew(filebox->fbox_path) : NULL;
}

/**
 * Initialize a new filebox from the specified path
 * @param file_path is the absolute path to the filebox file
 * @return NULL if the filebox could not be initialized
 */
uc_filebox_t *
filebox_from_file(const char * file_path);

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

static filebox_chunk_t *
filebox_get_chunk(uc_filebox_t * filebox, size_t chunk_id)
{
    size_t i = 0;
    filebox_chunk_entry_t * chunk_entry = TAILQ_FIRST(&filebox->chunk_list);

    for (; i < chunk_id; i++) {
        chunk_entry = TAILQ_NEXT(chunk_entry, next_entry);
    }

    return chunk_entry ? &chunk_entry->chunk : NULL;
}

static void
filebox_set_chunk(uc_filebox_t * filebox,
                  const filebox_chunk_t * chunk,
                  size_t chunk_id)
{
    size_t i = 0;
    filebox_chunk_entry_t * chunk_entry = TAILQ_FIRST(&filebox->chunk_list);

    for (; i < chunk_id; i++) {
        chunk_entry = TAILQ_NEXT(chunk_entry, next_entry);
    }

    if (chunk_entry) {
        memcpy(&chunk_entry->chunk, chunk, sizeof(filebox_chunk_t));
    }
}

#ifdef __cplusplus
}
#endif
