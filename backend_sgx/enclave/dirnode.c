#include "enclave_internal.h"

// This is how the dirnode will be serialized onto a buffer
struct __dirnode_hdr {
    struct nexus_uuid my_uuid;
    struct nexus_uuid root_uuid;

    uint32_t dir_entry_count; // number of files & subdirs
    uint32_t dir_entry_buflen;
} __attribute__((packed));



/* file and subdirectories in a folder */
struct dir_entry_s {
    uint16_t            total_len;
    nexus_dirent_type_t type;
    struct nexus_uuid   uuid;
    uint16_t            name_len;
    char                name[0];
} __attribute__((packed));




/**
 * Would be called as directory entries are freed
 * @param el
 */
static void
dirnode_dir_entry_deallocator(void * el);

// falls in style with the src->dst argument positions in libnexus
void
__copy_dir_entry(struct dir_entry_s * src_dir_entry, struct dir_entry_s * dst_dir_entry)
{
    memcpy(dst_dir_entry, src_dir_entry, src_dir_entry->total_len);
}

struct dir_entry_s *
clone_dir_entry(struct dir_entry_s * input_dir_entry)
{
    struct dir_entry_s * new_dir_entry = NULL;

    new_dir_entry = nexus_malloc(input_dir_entry->total_len);

    __copy_dir_entry(input_dir_entry, new_dir_entry);

    return new_dir_entry;
}

static void
initialize_dirnode_dir_entries(struct nexus_dirnode * dirnode)
{
    struct nexus_list * dir_entry_list = &dirnode->dir_entry_list;

    list_init(dir_entry_list);
    list_attributes_deallocator(dir_entry_list, dirnode_dir_entry_deallocator);
}

static uint8_t *
__parse_dirnode_header(struct nexus_dirnode * dirnode, uint8_t * buffer, size_t buflen)
{
    struct __dirnode_hdr * header = NULL;

    if (buflen < sizeof(struct __dirnode_hdr)) {
        log_error("buffer is too small for a dirnode\n");
        return NULL;
    }

    header = (struct __dirnode_hdr *)buffer;

    nexus_uuid_copy(&header->my_uuid, &dirnode->my_uuid);
    nexus_uuid_copy(&header->root_uuid, &dirnode->root_uuid);

    dirnode->dir_entry_count  = header->dir_entry_count;
    dirnode->dir_entry_buflen = header->dir_entry_buflen;

    return buffer + sizeof(struct __dirnode_hdr);
}

struct nexus_dirnode *
dirnode_from_buffer(uint8_t * buffer, size_t buflen)
{
    struct nexus_dirnode  * dirnode    = NULL;

    uint8_t * input_dir_entry_ptr = NULL;


    dirnode = nexus_malloc(sizeof(struct nexus_dirnode));

    input_dir_entry_ptr = __parse_dirnode_header(dirnode, buffer, buflen);

    if (input_dir_entry_ptr == NULL) {
        nexus_free(dirnode);

        log_error("__parse_dirnode_header FAILED\n");
        return NULL;
    }

    initialize_dirnode_dir_entries(dirnode);

    for (size_t i = 0; i < dirnode->dir_entry_count; i++) {
        struct dir_entry_s * new_dir_entry   = NULL;
        struct dir_entry_s * input_dir_entry = NULL;

        input_dir_entry = (struct dir_entry_s *)input_dir_entry_ptr;

        new_dir_entry = clone_dir_entry(input_dir_entry);

        list_append(&dirnode->dir_entry_list, new_dir_entry);

        input_dir_entry_ptr += input_dir_entry->total_len;
    }

    return dirnode;
}

static size_t
__get_total_size(struct nexus_dirnode * dirnode)
{
    return sizeof(struct __dirnode_hdr) + dirnode->dir_entry_buflen;
}

uint8_t *
__serialize_dirnode_header(struct nexus_dirnode * dirnode, uint8_t * buffer)
{
    struct __dirnode_hdr * header = (struct __dirnode_hdr *)buffer;

    nexus_uuid_copy(&dirnode->my_uuid, &header->my_uuid);
    nexus_uuid_copy(&dirnode->root_uuid, &header->root_uuid);

    header->dir_entry_count  = dirnode->dir_entry_count;
    header->dir_entry_buflen = dirnode->dir_entry_buflen;

    return buffer + sizeof(struct __dirnode_hdr);
}

static int
dirnode_serialize(struct nexus_dirnode * dirnode, uint8_t * buffer)
{
    uint8_t * output_ptr = NULL;

    output_ptr = __serialize_dirnode_header(dirnode, buffer);

    if (output_ptr == NULL) {
        log_error("serializing dirnode header FAILED\n");
        return -1;
    }

    {
        struct nexus_list * dir_entry_list = &dirnode->dir_entry_list;

        int ret = -1;


        ret = list_iterator_start(dir_entry_list); // returns 1 on success

        if (ret != 1) {
            log_error("could not start iterator\n");
            return -1;
        }

        // iterate through the dir entries and write to the buffer
        while (list_iterator_hasnext(dir_entry_list)) {
            struct dir_entry_s * dir_entry = list_iterator_next(dir_entry_list);

            size_t size = dir_entry->total_len;

            memcpy(output_ptr, dir_entry, size);

            output_ptr += size;
        }

        list_iterator_stop(dir_entry_list);
    }

    return 0;
}


struct nexus_dirnode *
dirnode_create(struct nexus_uuid * root_uuid)
{
    struct nexus_dirnode * dirnode = NULL;

    dirnode = nexus_malloc(sizeof(struct nexus_dirnode));

    nexus_uuid_gen(&dirnode->my_uuid);
    nexus_uuid_copy(root_uuid, &dirnode->root_uuid);

    initialize_dirnode_dir_entries(dirnode);

    return dirnode;
}

int
dirnode_store(struct nexus_dirnode   * dirnode,
              struct nexus_uuid_path * uuid_path,
              struct nexus_mac       * mac)
{
    struct nexus_crypto_buf * crypto_buffer = NULL;

    size_t    serialized_buflen = 0;

    int ret = -1;


    serialized_buflen = __get_total_size(dirnode);

    crypto_buffer = nexus_crypto_buf_new(serialized_buflen);
    if (!crypto_buffer) {
        goto out;
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

    // flush the buffer to the backend
    // XXX: maybe change API to crypto_buf_flush(...)
    ret = metadata_write(&dirnode->my_uuid, uuid_path, crypto_buffer);
    if (ret) {
        log_error("metadata_write FAILED\n");
        goto out;
    }

    ret = 0;
out:
    if (crypto_buffer) {
        nexus_crypto_buf_free(crypto_buffer);
    }

    return ret;
}

void
dirnode_free(struct nexus_dirnode * dirnode)
{
    list_destroy(&dirnode->dir_entry_list);
    nexus_free(dirnode);
}

// this will be called on list_destroy, list_remove
static void
dirnode_dir_entry_deallocator(void * el)
{
    struct dir_entry_s * dir_entry = (struct dir_entry_s *)el;

    nexus_free(dir_entry);
}

int
dirnode_add(struct nexus_dirnode * dirnode,
            char                 * filename,
            nexus_dirent_type_t    type,
            struct nexus_uuid    * entry_uuid)
{
    struct dir_entry_s * new_dir_entry = NULL;

    size_t name_len  = 0;
    size_t total_len = 0;

    name_len  = strlen(filename);
    total_len = sizeof(struct dir_entry_s) + name_len + 1;

    new_dir_entry = nexus_malloc(total_len);

    new_dir_entry->total_len = total_len;
    new_dir_entry->name_len  = name_len;
    new_dir_entry->type      = type;

    memcpy(new_dir_entry->name, filename, name_len);

    nexus_uuid_gen(&new_dir_entry->uuid);
    nexus_uuid_copy(&new_dir_entry->uuid, entry_uuid);

    dirnode->dir_entry_count += 1;
    dirnode->dir_entry_buflen += total_len;

    return 0;
}
