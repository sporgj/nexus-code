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



struct symlink_entry {
    uint8_t             total_len;
    struct nexus_uuid   uuid;
    uint16_t            target_len;
    char                target_path[0];
} __attribute__((packed));


static void
dirnode_init(struct nexus_dirnode * dirnode);


/**
 * Returns the size of the main bucket
 * @param dirnode
 * @return size
 */
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




static inline void
__dirnode_set_dirty(struct nexus_dirnode * dirnode)
{
    if (dirnode->metadata) {
        dirnode->metadata->is_dirty = true;
    }
}

static inline void
__dirnode_set_clean(struct nexus_dirnode * dirnode)
{
    if (dirnode->metadata) {
        dirnode->metadata->is_dirty = false;
    }
}



static void
__free_symlink_entry(void * el)
{
    struct symlink_entry * symlink = (struct symlink_entry *)el;

    nexus_free(symlink);
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

    return (input_ptr + nexus_acl_size(&dirnode->dir_acl));
}

static uint8_t *
__parse_symlinks(struct nexus_dirnode * dirnode, uint8_t * input_ptr)
{
    for (size_t i = 0; i < dirnode->symlink_count; i++) {
        struct symlink_entry * tmp_symlink_entry = (struct symlink_entry *)input_ptr;
        struct symlink_entry * new_symlink_entry = nexus_malloc(tmp_symlink_entry->total_len);

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
dirnode_from_crypto_buf(struct nexus_crypto_buf * crypto_buffer, nexus_io_flags_t flags)
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

    dirnode->mode = flags;

    return dirnode;
}

struct nexus_dirnode *
dirnode_load(struct nexus_uuid * uuid, nexus_io_flags_t flags)
{
    struct nexus_dirnode * dirnode = NULL;

    struct nexus_crypto_buf * crypto_buffer = nexus_crypto_buf_create(uuid, flags);

    if (crypto_buffer == NULL) {
        log_error("metadata_read FAILED\n");
        return NULL;
    }

    dirnode = dirnode_from_crypto_buf(crypto_buffer, flags);

    nexus_crypto_buf_free(crypto_buffer);

    return dirnode;
}


/********************    FILLDIR    *********************/
size_t
dirnode_readdir_total_size(struct nexus_dirnode * dirnode)
{
    // TODO
    return 0;
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
        struct symlink_entry * symlink_entry = list_iterator_get(iter);

        memcpy(output_ptr, symlink_entry, symlink_entry->total_len);

        output_ptr += symlink_entry->total_len;

        list_iterator_next(iter);
    }

    list_iterator_free(iter);

    return output_ptr;
}


/**
 * Write the bucket records in the specified buffer and returns a pointer to the
 * stored records.
 */
static inline uint8_t *
__serialize_bucket_records(struct nexus_dirnode * dirnode,
                           uint8_t              * output_ptr,
                           struct __bucket_rec ** stored_records)
{
    struct nexus_list_iterator * iter = list_iterator_new(&dirnode->bucket_list);

    *stored_records = (struct __bucket_rec *)output_ptr;

    while (list_iterator_is_valid(iter)) {
        struct dir_bucket   * bucket  = list_iterator_get(iter);

        struct __bucket_rec * record  = bucket_to_record(bucket, output_ptr);

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

            // removes the bucket metadata on disk
            buffer_layer_delete(&bucket->uuid);
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

    __dirnode_set_clean(dirnode);


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

static int
__filename_htable_cmp(const void                 * data,
                      const struct __hashed_name * entry1,
                      const struct __hashed_name * entry2,
                      const void                 * keydata)
{
    return strncmp(entry1->name, entry2->name, NEXUS_NAME_MAX);
}

static int
__fileuuid_htable_cmp(const void                 * data,
                      const struct __hashed_uuid * entry1,
                      const struct __hashed_uuid * entry2,
                      const void                 * keydata)
{
    return nexus_uuid_compare(entry1->uuid, entry2->uuid);
}

static struct dir_entry *
__dir_entry_from_hashed_filename(struct __hashed_name * hashed_filename)
{
    return container_of(hashed_filename, struct dir_entry, filename_hash);
}

static struct dir_entry *
__dir_entry_from_hashed_fileuuid(struct __hashed_uuid * hashed_fileuuid)
{
    return container_of(hashed_fileuuid, struct dir_entry, fileuuid_hash);
}


void
__dirnode_index_direntry(struct nexus_dirnode * dirnode, struct dir_entry * dir_entry)
{
    hashmap_put(&dirnode->filename_hashmap, &dir_entry->filename_hash);
    hashmap_put(&dirnode->fileuuid_hashmap, &dir_entry->fileuuid_hash);
}

void
__dirnode_forget_direntry(struct nexus_dirnode * dirnode, struct dir_entry * dir_entry)
{
    __hashmap_remove_entry(&dirnode->filename_hashmap, &dir_entry->filename_hash.hash_entry);
    __hashmap_remove_entry(&dirnode->fileuuid_hashmap, &dir_entry->fileuuid_hash.hash_entry);
}




void
__dirnode_add_direntry(struct nexus_dirnode * dirnode, struct dir_entry * dir_entry)
{
    struct dir_bucket * bucket = __get_available_bucket(dirnode);

    bucket_add_direntry(bucket, dir_entry);

    bucket->is_dirty = true;

    // add it to the main list
    {
        __dirnode_index_direntry(dirnode, dir_entry);

        dirnode->dir_entry_count  += 1;
        dirnode->dir_entry_buflen += dir_entry->dir_rec.rec_len;
    }

    __dirnode_set_dirty(dirnode);
}


static void
__dirnode_del_direntry(struct nexus_dirnode * dirnode, struct dir_entry * dir_entry)
{
    struct dir_bucket * bucket = dir_entry->bucket;

    bucket_del_direntry(bucket, dir_entry);

    bucket->is_dirty = true;

    {
        __dirnode_forget_direntry(dirnode, dir_entry);

        dirnode->dir_entry_count  -= 1;
        dirnode->dir_entry_buflen -= dir_entry->dir_rec.rec_len;
    }

    __dirnode_set_dirty(dirnode);
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
    hashmap_init(&dirnode->filename_hashmap, (hashmap_cmp_fn) __filename_htable_cmp, NULL, 16);
    hashmap_init(&dirnode->fileuuid_hashmap, (hashmap_cmp_fn) __fileuuid_htable_cmp, NULL, 16);

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
    // delete the dir_entries
    {
        struct dir_entry    * dir_entry = NULL;

        struct hashmap_iter   iter;

        hashmap_iter_init(&dirnode->filename_hashmap, &iter);

        do {
            struct __hashed_name * tmp = hashmap_iter_next(&iter);

            if (tmp == NULL) {
                break;
            }

            dir_entry = __dir_entry_from_hashed_filename(tmp);

            __dirnode_del_direntry(dirnode, dir_entry);
        } while(true);
    }

    hashmap_free(&dirnode->filename_hashmap, 0);
    hashmap_free(&dirnode->fileuuid_hashmap, 0);

    nexus_list_destroy(&dirnode->symlink_list);

    nexus_list_destroy(&dirnode->bucket_list);

    nexus_acl_free(&dirnode->dir_acl);

    nexus_free(dirnode);
}

static struct dir_entry *
__find_by_name(struct nexus_dirnode * dirnode, char * fname)
{
    struct __hashed_name * rst_hname = NULL;
    struct __hashed_name   tmp_hname;

    hashmap_entry_init(&tmp_hname.hash_entry, strhash(fname));
    tmp_hname.name = fname;

    rst_hname = hashmap_get(&dirnode->filename_hashmap, &tmp_hname, NULL);

    if (rst_hname == NULL) {
        return NULL;
    }

    return __dir_entry_from_hashed_filename(rst_hname);
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
    struct symlink_entry * symlink_entry = NULL;

    size_t target_len = 0;
    size_t total_len  = 0;


    // sets the dirnode dirty
    if (dirnode_add(dirnode, link_name, NEXUS_LNK, entry_uuid) != 0) {
        log_error("dirnode_add() FAILED\n");
        return -1;
    }

    target_len = strnlen(target_path, NEXUS_PATH_MAX);
    total_len  = target_len + sizeof(struct symlink_entry) + 1;

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
    struct __hashed_uuid * rst_huuid = NULL;
    struct __hashed_uuid   tmp_huuid;

    hashmap_entry_init(&tmp_huuid.hash_entry, memhash(uuid, sizeof(struct nexus_uuid)));
    tmp_huuid.uuid = uuid;

    rst_huuid = hashmap_get(&dirnode->fileuuid_hashmap, &tmp_huuid, NULL);

    if (rst_huuid == NULL) {
        return NULL;
    }

    return __dir_entry_from_hashed_fileuuid(rst_huuid);
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
    struct symlink_entry       * symlink_entry = NULL;

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
    struct symlink_entry        * symlink_entry = NULL;

    struct nexus_list_iterator * iter           = __find_symlink(dirnode, entry_uuid);

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
    struct symlink_entry       * symlink_entry = NULL;

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
