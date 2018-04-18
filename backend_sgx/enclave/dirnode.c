#include "enclave_internal.h"


#define BUCKET_CAPACITY  (128)


// This is how the dirnode will be serialized onto a buffer
struct __dirnode_hdr {
    struct nexus_uuid   my_uuid;
    struct nexus_uuid   root_uuid;

    uint32_t            symlink_count;
    uint32_t            symlink_buflen;

    uint32_t            dir_entry_count; // number of files & subdirs
    uint32_t            dir_entry_buflen;

    uint16_t            bucket_count;
} __attribute__((packed));


/* directory entry buffer on disk */
struct __dir_rec {
    uint16_t            rec_len;

    nexus_dirent_type_t type;

    struct nexus_uuid   uuid;

    uint16_t            name_len;

    char                name[NEXUS_NAME_MAX]; // XXX: waste of space...
} __attribute__((packed));


struct dir_entry {
    struct dir_bucket * bucket;

    struct __dir_rec    dir_rec;

    // the list of all dir_entries in the dirnode
    struct list_head    dir_list;

    // the list of all dir_entries in a specific bucket
    struct list_head    bckt_list;
};


struct symlink_entry_s {
    uint8_t             total_len;
    struct nexus_uuid   uuid;
    uint16_t            target_len;
    char                target_path[0];
} __attribute__((packed));



struct __bucket_rec {
    uint32_t            num_items;

    uint32_t            size_bytes;

    struct nexus_uuid   uuid;

    uint8_t             mac[NEXUS_MAC_SIZE];
} __attribute__((packed));


struct dir_bucket {
    bool                is_dirty;

    size_t              capacity;

    size_t              num_items;

    size_t              size_bytes;

    struct nexus_uuid   uuid;

    struct nexus_mac    mac;

    struct list_head    dir_entries;
};


#include "bucket.c"


static void
dirnode_init(struct nexus_dirnode * dirnode);


static inline void
__set_dirty(struct nexus_dirnode * dirnode)
{
    if (dirnode->metadata) {
        dirnode->metadata->is_dirty = true;
    }
}

static inline void
__set_clean(struct nexus_dirnode * dirnode)
{
    if (dirnode->metadata) {
        dirnode->metadata->is_dirty = false;
    }
}


static struct dir_entry *
__find_by_name(struct nexus_dirnode * dirnode, const char * fname)
{
    struct list_head * pos = NULL;

    size_t len = strlen(fname);

    list_for_each(pos, &dirnode->dir_entry_list) {
        struct dir_entry * dir_entry = list_entry(pos, struct dir_entry, dir_list);
        struct __dir_rec * dir_rec   = &dir_entry->dir_rec;

        if ((dir_rec->name_len == len) && (memcmp(dir_rec->name, fname, len) == 0)) {
            return dir_entry;
        }
    }

    return NULL;
}


static void
__free_symlink_entry(void * el)
{
    struct symlink_entry_s * symlink = (struct symlink_entry_s *)el;

    nexus_free(symlink);
}


static size_t
__get_bucket0_size(struct nexus_dirnode * dirnode)
{
    struct dir_bucket * bucket0 = nexus_list_get(&dirnode->bucket_list, 0);

    return sizeof(struct __dirnode_hdr)
           + dirnode->symlink_buflen
           + nexus_acl_size(&dirnode->dir_acl)
           + (sizeof(struct __bucket_rec) * dirnode->bucket_count)
           + bucket0->size_bytes;
}

static uint8_t *
__parse_dirnode_header(struct nexus_dirnode * dirnode, uint8_t * buffer, size_t buflen)
{
    struct __dirnode_hdr * header = (struct __dirnode_hdr *)buffer;

    if (buflen < sizeof(struct __dirnode_hdr)) {
        log_error("buffer is too small for a dirnode\n");
        return NULL;
    }

    nexus_uuid_copy(&header->my_uuid, &dirnode->my_uuid);
    nexus_uuid_copy(&header->root_uuid, &dirnode->root_uuid);

    dirnode->symlink_count    = header->symlink_count;
    dirnode->symlink_buflen   = header->symlink_buflen;

    dirnode->dir_entry_count  = header->dir_entry_count;
    dirnode->dir_entry_buflen = header->dir_entry_buflen;

    dirnode->bucket_count     = header->bucket_count;

    return buffer + sizeof(struct __dirnode_hdr);
}

static uint8_t *
__parse_acls(struct nexus_dirnode * dirnode, uint8_t * input_ptr, size_t bytes_left)
{
    if (__nexus_acl_from_buffer(&dirnode->dir_acl, input_ptr, bytes_left)) {
        log_error("__nexus_acl_from_buffer() FAILED\n");
        return NULL;
    }

    input_ptr += nexus_acl_size(&dirnode->dir_acl);

    return input_ptr;
}

static uint8_t *
__parse_symlinks(struct nexus_dirnode * dirnode, uint8_t * input_ptr)
{
    for (size_t i = 0; i < dirnode->symlink_count; i++) {
        struct symlink_entry_s * tmp_symlink_entry = (struct symlink_entry_s *)input_ptr;
        struct symlink_entry_s * new_symlink_entry = nexus_malloc(tmp_symlink_entry->total_len);

        memcpy(new_symlink_entry, tmp_symlink_entry, tmp_symlink_entry->total_len);

        input_ptr += (tmp_symlink_entry->total_len);

        nexus_list_append(&dirnode->symlink_list, new_symlink_entry);
    }

    return input_ptr;
}

/**
 * Parses the dirnode buckets in the buffer, and appends them to the dirnode
 */
static uint8_t *
__parse_bucket_records(struct nexus_dirnode * dirnode, uint8_t * input_ptr)
{
    for (size_t i = 0; i < dirnode->bucket_count; i++) {
        struct __bucket_rec * _rec   = (struct __bucket_rec *)input_ptr;

        struct dir_bucket   * bucket = bucket_from_record(BUCKET_CAPACITY, _rec);

        nexus_list_append(&dirnode->bucket_list, bucket);

        input_ptr += sizeof(struct __bucket_rec);
    }

    return input_ptr;
}

/**
 * Loads the content of bucket 0
 * @param dirnode
 * @return 0 on success
 */
static int
__load_bucket0(struct nexus_dirnode * dirnode, uint8_t * input_ptr)
{
    struct dir_bucket * bucket0 = nexus_list_get(&dirnode->bucket_list, 0);

    if (bucket_load_from_buffer(bucket0, dirnode, input_ptr)) {
        return -1;
    }

    return 0;
}

static int
__load_other_buckets(struct nexus_dirnode * dirnode)
{
    struct nexus_list_iterator * iter = list_iterator_new(&dirnode->bucket_list);

    int i   = 1; // skipping bucket0

    int ret = -1;


    list_iterator_next(iter);

    while (list_iterator_is_valid(iter)) {
        struct dir_bucket * bucket = list_iterator_get(iter);

        struct nexus_mac    mac;

        if (bucket_load_from_uuid(bucket, dirnode, &mac)) {
            log_error("bucket_load_from_uuid FAILED\n");
            goto out_err;
        }

        // make sure the correct version of the bucket is loaded
        if (nexus_mac_compare(&bucket->mac, &mac)) {
            log_error("bucket %d MAC validation failed\n", i);
            goto out_err;
        }

        i += 1;

        list_iterator_next(iter);
    }

    ret = 0;

out_err:
    list_iterator_free(iter);

    return ret;
}


struct nexus_dirnode *
dirnode_from_buffer(uint8_t * buffer, size_t buflen)
{
    struct nexus_dirnode * dirnode   = nexus_malloc(sizeof(struct nexus_dirnode));

    uint8_t              * input_ptr = __parse_dirnode_header(dirnode, buffer, buflen);

    if (input_ptr == NULL) {
        nexus_free(dirnode);

        log_error("__parse_dirnode_header FAILED\n");
        return NULL;
    }


    dirnode_init(dirnode);


    /* parse the main bucket info first */
    input_ptr = __parse_acls(dirnode, input_ptr, buflen);

    if (input_ptr == NULL) {
        log_error("could not parse symlinks\n");
        goto out_err;
    }


    input_ptr = __parse_symlinks(dirnode, input_ptr);

    if (input_ptr == NULL) {
        log_error("could not parse symlinks\n");
        goto out_err;
    }


    input_ptr = __parse_bucket_records(dirnode, input_ptr);

    if (input_ptr == NULL) {
        log_error("could not parse buckets\n");
        goto out_err;
    }


    /* load the dirnode buckets */
    if (__load_bucket0(dirnode, input_ptr)) {
        log_error("could not load dirnode buckets\n");
        goto out_err;
    }


    if (__load_other_buckets(dirnode)) {
        log_error("could not load dirnode buckets\n");
        goto out_err;
    }


    return dirnode;
out_err:
    dirnode_free(dirnode);

    return NULL;
}

struct nexus_dirnode *
dirnode_from_crypto_buf(struct nexus_crypto_buf * crypto_buffer)
{
    struct nexus_dirnode * dirnode = NULL;

    uint8_t * buffer = NULL;
    size_t    buflen = 0;


    buffer = nexus_crypto_buf_get(crypto_buffer, &buflen, NULL);

    if (buffer == NULL) {
        nexus_crypto_buf_free(crypto_buffer);
        log_error("nexus_crypto_buf_get() FAILED\n");
        return NULL;
    }

    dirnode = dirnode_from_buffer(buffer, buflen);

    if (dirnode == NULL) {
        log_error("__parse_dirnode FAILED\n");
        return NULL;
    }

    return dirnode;
}

struct nexus_dirnode *
dirnode_load(struct nexus_uuid * uuid)
{
    struct nexus_dirnode * dirnode = NULL;

    struct nexus_crypto_buf * crypto_buffer = nexus_crypto_buf_create(uuid);

    if (crypto_buffer == NULL) {
        log_error("metadata_read FAILED\n");
        return NULL;
    }

    dirnode = dirnode_from_crypto_buf(crypto_buffer);

    nexus_crypto_buf_free(crypto_buffer);

    return dirnode;
}


/********************    FILLDIR    *********************/
size_t
dirnode_readdir_total_size(struct nexus_dirnode * dirnode)
{
    size_t size = 0;

    struct list_head * pos = NULL;

    list_for_each(pos, &dirnode->dir_entry_list) {
        struct dir_entry * dir_entry = list_entry(pos, struct dir_entry, dir_list);

        // readdirs will contain pairs of names and UUIDs
        size += (dir_entry->dir_rec.name_len + sizeof(struct nexus_uuid));
    }

    return size;
}


/******************** SERIALIZATION ********************/

static uint8_t *
__serialize_dirnode_header(struct nexus_dirnode * dirnode, uint8_t * buffer)
{
    struct __dirnode_hdr * header = (struct __dirnode_hdr *)buffer;

    nexus_uuid_copy(&dirnode->my_uuid, &header->my_uuid);
    nexus_uuid_copy(&dirnode->root_uuid, &header->root_uuid);

    header->symlink_count    = dirnode->symlink_count;
    header->symlink_buflen   = dirnode->symlink_buflen;

    header->dir_entry_count  = dirnode->dir_entry_count;
    header->dir_entry_buflen = dirnode->dir_entry_buflen;

    header->bucket_count     = dirnode->bucket_count;

    return buffer + sizeof(struct __dirnode_hdr);
}

static inline uint8_t *
__serialize_acls(struct nexus_dirnode * dirnode, uint8_t * output_ptr)
{
    if (nexus_acl_to_buffer(&dirnode->dir_acl, output_ptr)) {
        log_error("nexus_acl_to_buffer() FAILED\n");
        return NULL;
    }

    return output_ptr + nexus_acl_size(&dirnode->dir_acl);
}


static inline uint8_t *
__serialize_symlinks(struct nexus_dirnode * dirnode, uint8_t * output_ptr)
{
    struct nexus_list_iterator * iter = list_iterator_new(&dirnode->symlink_list);

    while (list_iterator_is_valid(iter)) {
        struct symlink_entry_s * symlink_entry = list_iterator_get(iter);

        memcpy(output_ptr, symlink_entry, symlink_entry->total_len);

        output_ptr += symlink_entry->total_len;

        list_iterator_next(iter);
    }

    list_iterator_free(iter);

    return output_ptr;
}


/**
 * Write the bucket records in the specified buffer and returns a pointer to the
 * stored buckets.
 */
static inline uint8_t *
__serialize_bucket_records(struct nexus_dirnode * dirnode,
                           uint8_t              * output_ptr,
                           struct __bucket_rec ** records)
{
    struct nexus_list_iterator * iter = list_iterator_new(&dirnode->bucket_list);

    *records = (struct __bucket_rec *)output_ptr;

    while (list_iterator_is_valid(iter)) {
        struct dir_bucket   * bucket  = list_iterator_get(iter);

        struct __bucket_rec * record  = __bucket_to_record(bucket, output_ptr);

        output_ptr += sizeof(*record);

        list_iterator_next(iter);
    }

    list_iterator_free(iter);

    return output_ptr;
}

static inline int
__store_bucket0(struct nexus_dirnode * dirnode, uint8_t * output_ptr)
{
    struct dir_bucket * bucket0 = nexus_list_get(&dirnode->bucket_list, 0);

    if (bucket_serialize(bucket0, output_ptr)) {
        return -1;
    }

    bucket0->is_dirty = false;

    return 0;
}


static inline int
__store_other_buckets(struct nexus_dirnode * dirnode, struct __bucket_rec * record)
{
    struct nexus_list_iterator * iter = list_iterator_new(&dirnode->bucket_list);

    int i   = 0;


    // skipping bucket0
    i      += 1;
    record += 1;
    list_iterator_next(iter);

    while (list_iterator_is_valid(iter)) {
        struct dir_bucket * bucket = list_iterator_get(iter);

        if (!bucket->is_dirty) {
            goto skip;
        }

        // store the bucket and write the mac into its matching record
        if (bucket_store(bucket)) {
            list_iterator_free(iter);

            log_error("bucket_load_from_uuid FAILED\n");
            return -1;
        }

        bucket->is_dirty = false;

        nexus_mac_to_buf(&bucket->mac, record->mac);
skip:
        i      += 1;
        record += 1;
        list_iterator_next(iter);
    }

    list_iterator_free(iter);

    return 0;
}

static void
__delete_empty_dirnode_buckets(struct nexus_dirnode * dirnode)
{
    struct nexus_list_iterator * iter = list_iterator_new(&dirnode->bucket_list);

    // we skip over the first one
    list_iterator_next(iter);

    while (list_iterator_is_valid(iter)) {
        struct dir_bucket * bucket = list_iterator_get(iter);

        if (bucket->is_dirty && bucket->num_items == 0) {
            dirnode->bucket_count -= 1;

            bucket_delete(bucket);
            list_iterator_del(iter); // calls bucket_destroy
            continue;
        }

        list_iterator_next(iter);
    }
}


static int
dirnode_serialize(struct nexus_dirnode * dirnode, uint8_t * buffer)
{
    struct __bucket_rec * bucket_records = NULL;

    uint8_t             * output_ptr     = NULL;


    __delete_empty_dirnode_buckets(dirnode);


    output_ptr = __serialize_dirnode_header(dirnode, buffer);

    if (output_ptr == NULL) {
        log_error("serializing dirnode header FAILED\n");
        return -1;
    }


    output_ptr = __serialize_acls(dirnode, output_ptr);

    if (output_ptr == NULL) {
        log_error("could not serialize acls\n");
        return -1;
    }


    output_ptr = __serialize_symlinks(dirnode, output_ptr);

    if (output_ptr == NULL) {
        log_error("could not serialize symlinks\n");
        return -1;
    }


    output_ptr = __serialize_bucket_records(dirnode, output_ptr, &bucket_records);

    if (output_ptr == NULL) {
        log_error("could not serialize bucket records\n");
        return -1;
    }


    if (__store_bucket0(dirnode, output_ptr)) {
        log_error("could not store bucket0\n");
        return -1;
    }


    if (__store_other_buckets(dirnode, bucket_records)) {
        log_error("could not store dirnode buckets\n");
        return -1;
    }

    return 0;
}

int
dirnode_store(struct nexus_uuid    * uuid,
              struct nexus_dirnode * dirnode,
              uint32_t               version,
              struct nexus_mac     * mac)
{
    struct nexus_crypto_buf * crypto_buffer = NULL;

    size_t                    bucket0_size  = __get_bucket0_size(dirnode);

    int                       ret           = -1;


    crypto_buffer = nexus_crypto_buf_new(bucket0_size, version, uuid);

    if (crypto_buffer == NULL) {
        return -1;
    }


    // write to the buffer
    {
        uint8_t * output_buffer = NULL;

        size_t    buffer_size   = 0;


        output_buffer = nexus_crypto_buf_get(crypto_buffer, &buffer_size, NULL);

        if (output_buffer == NULL) {
            log_error("could not get the crypto_buffer buffer\n");
            goto out;
        }


        ret = dirnode_serialize(dirnode, output_buffer);

        if (ret != 0) {
            log_error("dirnode_serialize() FAILED\n");
            goto out;
        }


        ret = nexus_crypto_buf_put(crypto_buffer, mac);

        if (ret != 0) {
            log_error("nexus_crypto_buf_put FAILED\n");
            goto out;
        }
    }


    ret = nexus_crypto_buf_flush(crypto_buffer);

    if (ret) {
        log_error("metadata_write FAILED\n");
        goto out;
    }

    __set_clean(dirnode);


    ret = 0;
out:
    nexus_crypto_buf_free(crypto_buffer);

    return ret;
}


// searches dirnode for an available bucket. if full, creates a new bucket
static struct dir_bucket *
__get_available_bucket(struct nexus_dirnode * dirnode)
{
    struct dir_bucket          * bucket  = NULL;

    struct nexus_list_iterator * iter    = list_iterator_new(&dirnode->bucket_list);

    while (list_iterator_is_valid(iter)) {
        bucket = list_iterator_get(iter);

        if (bucket->num_items < bucket->capacity) {
            list_iterator_free(iter);

            return bucket;
        }

        list_iterator_next(iter);
    }

    list_iterator_free(iter);


    // if none was found, just create a new bucket
    bucket = bucket_create(BUCKET_CAPACITY);

    nexus_list_append(&dirnode->bucket_list, bucket);

    dirnode->bucket_count += 1;

    return bucket;
}


void
__dirnode_add_direntry(struct nexus_dirnode * dirnode, struct dir_entry * dir_entry)
{
    struct dir_bucket * bucket = __get_available_bucket(dirnode);

    bucket_add_direntry(bucket, dir_entry);

    bucket->is_dirty = true;

    // add it to the main list
    {
        list_add_tail(&dir_entry->dir_list, &dirnode->dir_entry_list);

        dirnode->dir_entry_count  += 1;
        dirnode->dir_entry_buflen += dir_entry->dir_rec.rec_len;
    }

    __set_dirty(dirnode);
}


static void
__dirnode_del_direntry(struct nexus_dirnode * dirnode, struct dir_entry * dir_entry)
{
    struct dir_bucket * bucket = dir_entry->bucket;

    bucket_del_direntry(bucket, dir_entry);

    bucket->is_dirty = true;

    {
        list_del(&dir_entry->dir_list);

        dirnode->dir_entry_count  -= 1;
        dirnode->dir_entry_buflen -= dir_entry->dir_rec.rec_len;
    }

    __set_dirty(dirnode);
}


static void
__remove_and_free_bucket(void * el)
{
    struct dir_bucket * bucket = (struct dir_bucket *) el;

    bucket_destroy(bucket);
}

static void
dirnode_init(struct nexus_dirnode * dirnode)
{
    INIT_LIST_HEAD(&dirnode->dir_entry_list);

    nexus_list_init(&dirnode->bucket_list);
    nexus_list_set_deallocator(&dirnode->bucket_list, __remove_and_free_bucket);

    nexus_list_init(&dirnode->symlink_list);
    nexus_list_set_deallocator(&dirnode->symlink_list, __free_symlink_entry);

    nexus_acl_init(&dirnode->dir_acl);
}


struct nexus_dirnode *
dirnode_create(struct nexus_uuid * root_uuid, struct nexus_uuid * my_uuid)
{
    struct nexus_dirnode * dirnode = nexus_malloc(sizeof(struct nexus_dirnode));

    nexus_uuid_copy(root_uuid, &dirnode->root_uuid);
    nexus_uuid_copy(my_uuid, &dirnode->my_uuid);

    dirnode_init(dirnode);

    // create bucket0
    __get_available_bucket(dirnode);

    return dirnode;
}

void
dirnode_free(struct nexus_dirnode * dirnode)
{
    struct list_head * dir_entry_list = &dirnode->dir_entry_list;

    while (!list_empty(dir_entry_list)) {
        struct dir_entry * dir_entry = list_first_entry(dir_entry_list, struct dir_entry, dir_list);

        __dirnode_del_direntry(dirnode, dir_entry);
    }

    nexus_list_destroy(&dirnode->symlink_list);

    nexus_list_destroy(&dirnode->bucket_list);

    nexus_acl_free(&dirnode->dir_acl);

    nexus_free(dirnode);
}

int
dirnode_add(struct nexus_dirnode * dirnode,
            char                 * filename,
            nexus_dirent_type_t    type,
            struct nexus_uuid    * entry_uuid)
{
    struct dir_entry * new_dir_entry = NULL;

    // check for existing entry.
    // XXX: typical filesystems perform a lookup to check if the file exists before
    // adding the file. Consider caching dirnode lookups
    if (__find_by_name(dirnode, filename)) {
        return -1;
    }

    new_dir_entry = __new_dir_entry(entry_uuid, type, filename);

    __dirnode_add_direntry(dirnode, new_dir_entry);

    return 0;
}

int
dirnode_add_link(struct nexus_dirnode * dirnode,
                 char                 * link_name,
                 char                 * target_path,
                 struct nexus_uuid    * entry_uuid)
{
    struct symlink_entry_s * symlink_entry = NULL;

    size_t target_len = 0;
    size_t total_len  = 0;


    // sets the dirnode dirty
    if (dirnode_add(dirnode, link_name, NEXUS_LNK, entry_uuid) != 0) {
        log_error("dirnode_add() FAILED\n");
        return -1;
    }

    target_len = strnlen(target_path, NEXUS_PATH_MAX);
    total_len  = target_len + sizeof(struct symlink_entry_s) + 1;

    symlink_entry = nexus_malloc(total_len);

    symlink_entry->total_len  = total_len;
    symlink_entry->target_len = target_len;

    nexus_uuid_copy(entry_uuid, &symlink_entry->uuid);
    memcpy(symlink_entry->target_path, target_path, target_len);

    nexus_list_append(&dirnode->symlink_list, symlink_entry);

    dirnode->symlink_count  += 1;
    dirnode->symlink_buflen += total_len;

    return 0;
}

static struct dir_entry *
__find_by_uuid(struct nexus_dirnode * dirnode, struct nexus_uuid * uuid)
{
    struct list_head * pos = NULL;

    list_for_each(pos, &dirnode->dir_entry_list) {
        struct dir_entry * dir_entry = list_entry(pos, struct dir_entry, dir_list);

        if (nexus_uuid_compare(&dir_entry->dir_rec.uuid, uuid) == 0) {
            return dir_entry;
        }
    }

    return NULL;
}

int
dirnode_find_by_uuid(struct nexus_dirnode * dirnode,
                     struct nexus_uuid    * uuid,
                     nexus_dirent_type_t  * p_type,
                     const char          ** p_fname,
                     size_t               * p_fname_len)
{
    struct __dir_rec * dir_rec   = NULL;

    struct dir_entry * dir_entry = __find_by_uuid(dirnode, uuid);

    if (dir_entry == NULL) {
        return -1;
    }

    dir_rec      = &dir_entry->dir_rec;

    *p_type      = dir_rec->type;
    *p_fname     = dir_rec->name;
    *p_fname_len = dir_rec->name_len;

    return 0;
}

int
dirnode_find_by_name(struct nexus_dirnode * dirnode,
                     char                 * filename,
                     nexus_dirent_type_t  * type,
                     struct nexus_uuid    * entry_uuid)
{
    struct dir_entry * dir_entry = __find_by_name(dirnode, filename);

    if (dir_entry == NULL) {
        return -1;
    }

    *type = dir_entry->dir_rec.type;

    nexus_uuid_copy(&dir_entry->dir_rec.uuid, entry_uuid);

    return 0;
}

static struct nexus_list_iterator *
__find_symlink(struct nexus_dirnode * dirnode, struct nexus_uuid * uuid)
{
    struct symlink_entry_s     * symlink_entry = NULL;

    struct nexus_list_iterator * iter          = NULL;

    iter = list_iterator_new(&dirnode->symlink_list);

    while (list_iterator_is_valid(iter)) {
        symlink_entry = list_iterator_get(iter);

        if (nexus_uuid_compare(&symlink_entry->uuid, uuid) == 0) {
            return iter;
        }

        list_iterator_next(iter);
    }

    list_iterator_free(iter);

    return NULL;
}

static int
__remove_symlink(struct nexus_dirnode * dirnode,
                 struct nexus_uuid    * entry_uuid,
                 char                ** target_path_dest)
{
    struct symlink_entry_s * symlink_entry = NULL;

    struct nexus_list_iterator * iter      = __find_symlink(dirnode, entry_uuid);

    if (iter == NULL) {
        return -1;
    }

    symlink_entry = list_iterator_get(iter);

    if (target_path_dest) {
        *target_path_dest = strndup(symlink_entry->target_path, NEXUS_PATH_MAX);
    }

    dirnode->symlink_count  -= 1;
    dirnode->symlink_buflen -= symlink_entry->total_len;

    list_iterator_del(iter);
    list_iterator_free(iter);

    return 0;
}

char *
dirnode_get_link(struct nexus_dirnode * dirnode, struct nexus_uuid * entry_uuid)
{
    struct symlink_entry_s     * symlink_entry = NULL;

    struct nexus_list_iterator * iter          = __find_symlink(dirnode, entry_uuid);

    if (iter == NULL) {
        return NULL;
    }

    symlink_entry = list_iterator_get(iter);

    list_iterator_free(iter);

    return strndup(symlink_entry->target_path, NEXUS_PATH_MAX);
}

static inline int
__dirnode_remove(struct nexus_dirnode * dirnode,
                 char                 * filename,
                 nexus_dirent_type_t  * type,
                 struct nexus_uuid    * entry_uuid)
{
    struct dir_entry * dir_entry = __find_by_name(dirnode, filename);

    if (dir_entry == NULL) {
        return -1;
    }


    *type = dir_entry->dir_rec.type;

    nexus_uuid_copy(&dir_entry->dir_rec.uuid, entry_uuid);


    __dirnode_del_direntry(dirnode, dir_entry);

    __free_dir_entry(dir_entry);

    return 0;
}

int
dirnode_remove(struct nexus_dirnode * dirnode,
               char                 * filename,
               nexus_dirent_type_t  * type,
               struct nexus_uuid    * entry_uuid,
               char                ** symlink_target_path)
{
    int ret = __dirnode_remove(dirnode, filename, type, entry_uuid);

    if (*type == NEXUS_LNK) {
        __remove_symlink(dirnode, entry_uuid, symlink_target_path);
    }

    return ret;
}
