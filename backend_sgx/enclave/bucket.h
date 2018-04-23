#pragma once

#include <stdlib.h>
#include <stdint.h>
#include <string.h>


struct dirnode;

// bucket record serialized into the main dirnode
struct __bucket_rec {
    uint32_t            num_items;

    uint32_t            size_bytes;

    struct nexus_uuid   uuid;

    uint8_t             mac[NEXUS_MAC_SIZE];
} __attribute__((packed));


// the bucket in memory
struct dir_bucket {
    bool                is_dirty;

    size_t              capacity;

    size_t              num_items;

    size_t              size_bytes;

    struct nexus_uuid   uuid;

    struct nexus_mac    mac;

    struct list_head    dir_entries;
};


struct dir_bucket *
bucket_create(size_t capacity);

void
bucket_destroy(struct dir_bucket * bucket);



/**
 * Writes the bucket record on the output buffer and returns a pointer
 * to the record
 * @param bucket
 * @param output_ptr
 */
struct __bucket_rec *
bucket_to_record(struct dir_bucket * bucket, uint8_t * output_ptr);


/**
 * Initializes a bucket object with the given capacity
 * @param capacity
 * @param _rec
 * @return dir_bucket
 */
struct dir_bucket *
bucket_from_record(size_t capacity, struct __bucket_rec * _rec);


/**
 * Loads the bucket content from a buccket
 * @param bucket
 * @param dirnode
 * @param input_ptr
 * return 0 on success
 */
int
bucket_load_from_buffer(struct dir_bucket * bucket, struct nexus_dirnode * dirnode, uint8_t * input_ptr);

int
bucket_load_from_uuid(struct dir_bucket    * bucket,
                      struct nexus_dirnode * dirnode,
                      struct nexus_mac     * mac);

int
bucket_serialize(struct dir_bucket * bucket, uint8_t * buffer);

int
bucket_store(struct dir_bucket * bucket);


int
bucket_add_direntry(struct dir_bucket * bucket, struct dir_entry * dir_entry);

int
bucket_del_direntry(struct dir_bucket * bucket, struct dir_entry * dir_entry);





// dir entry API

struct dir_entry *
__new_dir_entry(struct nexus_uuid * entry_uuid, nexus_dirent_type_t type, char * filename);

void
__free_dir_entry(struct dir_entry * dir_entry);


