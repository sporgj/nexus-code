#include "enclave_internal.h"


static inline void
__init_dir_entry(struct dir_entry * dir_entry)
{
    struct __hashed_name * filename_hash = &dir_entry->filename_hash;
    struct __hashed_uuid * fileuuid_hash = &dir_entry->fileuuid_hash;

    filename_hash->name = dir_entry->dir_rec.name;
    fileuuid_hash->uuid = &dir_entry->dir_rec.link_uuid;

    hashmap_entry_init(&filename_hash->hash_entry, strhash(filename_hash->name));
    hashmap_entry_init(&fileuuid_hash->hash_entry,
                       memhash(fileuuid_hash->uuid, sizeof(struct nexus_uuid)));

    INIT_LIST_HEAD(&dir_entry->dent_list);
    INIT_LIST_HEAD(&dir_entry->bckt_list);
}

struct dir_entry *
__new_dir_entry(struct nexus_uuid * entry_uuid, nexus_dirent_type_t type, char * filename)
{
    struct dir_entry  * new_dir_entry = nexus_malloc(sizeof(struct dir_entry));

    struct __dir_rec  * dir_rec       = &new_dir_entry->dir_rec;


    dir_rec->name_len = strlen(filename);
    dir_rec->rec_len  = sizeof(struct __dir_rec) - (NEXUS_NAME_MAX - dir_rec->name_len) + 1;
    dir_rec->type     = type;

    memcpy(dir_rec->name, filename, dir_rec->name_len);

    // when creating a file, real and link UUIDs are the same
    nexus_uuid_copy(entry_uuid, &dir_rec->link_uuid);
    nexus_uuid_copy(entry_uuid, &dir_rec->real_uuid);

    __init_dir_entry(new_dir_entry);

    return new_dir_entry;
}

void
__free_dir_entry(struct dir_entry * dir_entry)
{
    nexus_free(dir_entry);
}

static uint8_t *
__parse_dir_entry(struct dir_entry ** result_dir_entry, uint8_t * in_buffer)
{
    struct dir_entry * new_dir_entry = nexus_malloc(sizeof(struct dir_entry));

    struct __dir_rec * tmp_dirbuf    = (struct __dir_rec *)in_buffer;

    memcpy(&new_dir_entry->dir_rec, tmp_dirbuf, tmp_dirbuf->rec_len);

    __init_dir_entry(new_dir_entry);


    *result_dir_entry = new_dir_entry;

    return (in_buffer + tmp_dirbuf->rec_len);
}

static uint8_t *
__serialize_dir_entry(struct dir_entry * dir_entry, uint8_t * out_buffer)
{
    size_t rec_len = dir_entry->dir_rec.rec_len;

    memcpy(out_buffer, &dir_entry->dir_rec, rec_len);

    return (out_buffer + rec_len);
}



struct dir_bucket *
bucket_create(size_t capacity)
{
    struct dir_bucket * bucket = nexus_malloc(sizeof(struct dir_bucket));

    nexus_uuid_gen(&bucket->uuid);

    INIT_LIST_HEAD(&bucket->dir_entries);

    bucket->capacity = capacity;

    return bucket;
}

void
bucket_destroy(struct dir_bucket * bucket)
{
    nexus_free(bucket);
}

struct dir_bucket *
bucket_from_record(size_t capacity, struct __bucket_rec * _rec)
{
    struct dir_bucket * bucket = nexus_malloc(sizeof(struct dir_bucket));

    bucket->capacity           = capacity;
    bucket->num_items          = _rec->num_items;
    bucket->size_bytes         = _rec->size_bytes;

    __nexus_mac_from_buf(&bucket->mac, _rec->mac);
    nexus_uuid_copy(&_rec->uuid, &bucket->uuid);

    INIT_LIST_HEAD(&bucket->dir_entries);

    return bucket;
}

struct __bucket_rec *
bucket_to_record(struct dir_bucket * bucket, uint8_t * output_ptr)
{
    struct __bucket_rec * _rec = (struct __bucket_rec *)output_ptr;

    _rec->num_items            = bucket->num_items;
    _rec->size_bytes           = bucket->size_bytes;

    nexus_uuid_copy(&bucket->uuid, &_rec->uuid);
    nexus_mac_to_buf(&bucket->mac, _rec->mac);

    return _rec;
}

int
bucket_load_from_buffer(struct dir_bucket    * bucket,
                        struct nexus_dirnode * dirnode,
                        uint8_t              * input_ptr)
{

    for (size_t i = 0; i < bucket->num_items; i++) {
        struct dir_entry * new_dir_entry = NULL;

        input_ptr = __parse_dir_entry(&new_dir_entry, input_ptr);

        list_add_tail(&new_dir_entry->bckt_list, &bucket->dir_entries);

        new_dir_entry->bucket = bucket;

        __dirnode_index_direntry(dirnode, new_dir_entry);
    }


    return 0;
}

/**
 * Loads a bucket from the datastore
 */
int
bucket_load_from_uuid(struct dir_bucket    * bucket,
                      struct nexus_dirnode * dirnode,
                      nexus_io_flags_t       flags,
                      struct nexus_mac     * mac)
{
    struct nexus_crypto_buf * crypto_buffer = nexus_crypto_buf_create(&bucket->uuid, flags);

    if (crypto_buffer == NULL) {
        log_error("metadata_read FAILED\n");
        return -1;
    }

    {
        uint8_t * buffer = NULL;
        size_t    buflen = 0;

        buffer = nexus_crypto_buf_get(crypto_buffer, &buflen, mac);

        if (buffer == NULL) {
            log_error("nexus_crypto_buf_get() FAILED\n");
            goto out_err;
        }

        if (bucket_load_from_buffer(bucket, dirnode, buffer)) {
            log_error("bucket_load_from_buffer() FAILED\n");
            goto out_err;
        }
    }

    bucket->on_disk = true;

    nexus_crypto_buf_free(crypto_buffer);

    return 0;

out_err:
    nexus_crypto_buf_free(crypto_buffer);

    return -1;
}

int
bucket_serialize(struct dir_bucket * bucket, uint8_t * buffer)
{
    struct list_head    * pos        = NULL;

    uint8_t             * output_ptr = buffer;

    struct dir_entry    * dir_entry  = NULL;


    list_for_each(pos, &bucket->dir_entries) {
        dir_entry  = list_entry(pos, struct dir_entry, bckt_list);

        output_ptr = __serialize_dir_entry(dir_entry, output_ptr);
    }

    bucket->is_dirty = false;

    return 0;
}

/**
 * Writes the bucket's dir entries to the datastore
 * @param bucket
 * @return 0 on success
 */
int
bucket_store(struct dir_bucket * bucket)
{
    struct nexus_crypto_buf * crypto_buffer = NULL;

    uint8_t                 * buffer        = NULL;

    size_t                    buflen        = 0;


    if (!bucket->on_disk && buffer_layer_new(&bucket->uuid)) {
        log_error("could not create bucket metadata file on disk\n");
        return -1;
    }

    bucket->on_disk = true;


    crypto_buffer = nexus_crypto_buf_new(bucket->size_bytes, 0, &bucket->uuid);

    if (crypto_buffer == NULL) {
        log_error("could not create crypto buffer FAILED\n");
        return -1;
    }

    buffer = nexus_crypto_buf_get(crypto_buffer, &buflen, NULL);

    if (buffer == NULL) {
        log_error("nexus_crypto_buf_get() FAILED\n");
        goto out_err;
    }

    if (bucket_serialize(bucket, buffer)) {
        log_error("bucket_serialize() FAILED\n");
        goto out_err;
    }

    if (nexus_crypto_buf_put(crypto_buffer, &bucket->mac)) {
        log_error("crypto_buf_put FAILED\n");
        goto out_err;
    }

    nexus_crypto_buf_free(crypto_buffer);

    return 0;
out_err:
    nexus_crypto_buf_free(crypto_buffer);

    return -1;
}

int
bucket_add_direntry(struct dir_bucket * bucket, struct dir_entry * dir_entry)
{
    // XXX
    if ((bucket->num_items >= bucket->capacity) || (dir_entry->bucket)) {
        return -1;
    }


    bucket->num_items  += 1;
    bucket->size_bytes += dir_entry->dir_rec.rec_len;

    list_add_tail(&dir_entry->bckt_list, &bucket->dir_entries);

    dir_entry->bucket   = bucket;

    return 0;
}

int
bucket_del_direntry(struct dir_bucket * bucket, struct dir_entry * dir_entry)
{
    // XXX might be too much
    if ((bucket->num_items == 0) || (bucket != dir_entry->bucket)) {
        return -1;
    }

    bucket->num_items  -= 1;
    bucket->size_bytes -= dir_entry->dir_rec.rec_len;

    list_del(&dir_entry->bckt_list);

    dir_entry->bucket   = NULL;

    return 0;
}
