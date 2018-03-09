#include "enclave_internal.h"

struct __filenode_hdr {
    struct nexus_uuid my_uuid;
    struct nexus_uuid root_uuid;

    uint32_t nchunks;
    uint8_t  log2chunksize;
    uint64_t filesize;
} __attribute__((packed));

struct chunk_entry_s {
    struct nexus_crypto_ctx crypto_ctx;
} __attribute__((packed));


static inline size_t
get_chunk_number(struct nexus_filenode * filenode, size_t offset)
{
    return ((offset < filenode->chunksize)
                ? 0
                : 1 + ((offset - (size_t)filenode->chunksize) >> filenode->log2chunksize));
}

static inline size_t
get_chunk_count(struct nexus_filenode * filenode, size_t file_size)
{
    return get_chunk_number(filenode, file_size) + 1;
}



static void
__free_chunk_entry(void * element)
{
    free(element);
}


static size_t
__get_filenode_size(struct nexus_filenode * filenode)
{
    return sizeof(struct __filenode_hdr) + (filenode->nchunks * sizeof(struct chunk_entry_s));
}

static void
filenode_set_chunksize(struct nexus_filenode * filenode, size_t log2chunksize)
{
    filenode->log2chunksize = log2chunksize;
    filenode->chunksize     = 1 << log2chunksize;
}

static void
filenode_init(struct nexus_filenode * filenode, size_t log2chunksize)
{
    filenode_set_chunksize(filenode, log2chunksize);

    nexus_list_init(&filenode->chunk_list);
    nexus_list_set_deallocator(&filenode->chunk_list, __free_chunk_entry);
}

struct nexus_filenode *
filenode_create(struct nexus_uuid * root_uuid, struct nexus_uuid * my_uuid)
{
    struct nexus_filenode * filenode = NULL;

    filenode = nexus_malloc(sizeof(struct nexus_filenode));

    nexus_uuid_copy(root_uuid, &filenode->root_uuid);
    nexus_uuid_copy(my_uuid, &filenode->my_uuid);

    filenode_init(filenode, global_log2chunk_size);

    return filenode;
}

static uint8_t *
__parse_filenode_header(struct nexus_filenode * filenode, uint8_t * buffer, size_t buflen)
{
    struct __filenode_hdr * header = NULL;

    if (buflen < sizeof(struct __filenode_hdr)) {
        log_error("buffer is too small to fit a filenode\n");
        return NULL;
    }


    header = (struct __filenode_hdr *)buffer;

    filenode->nchunks  = header->nchunks;
    filenode->filesize = header->filesize;

    nexus_uuid_copy(&header->my_uuid, &filenode->my_uuid);
    nexus_uuid_copy(&header->root_uuid, &filenode->root_uuid);

    filenode_init(filenode, header->log2chunksize);

    return (buffer + sizeof(struct __filenode_hdr));
}

struct nexus_filenode *
filenode_from_buffer(uint8_t * buffer, size_t buflen)
{
    struct nexus_filenode * filenode = NULL;

    struct chunk_entry_s * new_chunk_entry = NULL;
    struct chunk_entry_s * tmp_chunk_entry = NULL;

    uint8_t * input_ptr = NULL;


    filenode = nexus_malloc(sizeof(struct nexus_filenode));

    input_ptr = __parse_filenode_header(filenode, buffer, buflen);

    if (input_ptr == NULL) {
        nexus_free(filenode);
        log_error("could not parse filenode header\n");
        return NULL;
    }

    tmp_chunk_entry = (struct chunk_entry_s *) input_ptr;

    for (size_t i = 0; i < filenode->nchunks; i++) {
        new_chunk_entry = nexus_malloc(sizeof(struct chunk_entry_s));

        memcpy(new_chunk_entry, tmp_chunk_entry, sizeof(struct chunk_entry_s));

        nexus_list_append(&filenode->chunk_list, new_chunk_entry);

        tmp_chunk_entry++;
    }

    return filenode;
}

struct nexus_filenode *
filenode_load(struct nexus_uuid * uuid)
{
    struct nexus_filenode * filenode = NULL;

    struct nexus_crypto_buf * crypto_buffer = NULL;

    uint8_t * buffer = NULL;
    size_t    buflen = 0;


    crypto_buffer = nexus_crypto_buf_create(uuid);

    if (crypto_buffer == NULL) {
        log_error("metadata_read FAILED\n");
        return NULL;
    }

    buffer = nexus_crypto_buf_get(crypto_buffer, &buflen, NULL);

    if (buffer == NULL) {
        nexus_crypto_buf_free(crypto_buffer);
        log_error("nexus_crypto_buf_get() FAILED\n");
        return NULL;
    }

    filenode = filenode_from_buffer(buffer, buflen);

    nexus_crypto_buf_free(crypto_buffer);

    if (filenode == NULL) {
        log_error("__parse_filenode FAILED\n");
        return NULL;
    }

    return filenode;
}

static uint8_t *
__serialize_filenode_header(struct nexus_filenode * filenode, uint8_t * buffer)
{
    struct __filenode_hdr * header = NULL;

    header = (struct __filenode_hdr *)buffer;

    header->nchunks       = filenode->nchunks;
    header->log2chunksize = filenode->log2chunksize;
    header->filesize      = filenode->filesize;

    nexus_uuid_copy(&filenode->my_uuid, &header->my_uuid);
    nexus_uuid_copy(&filenode->root_uuid, &header->root_uuid);

    memcpy(buffer, header, sizeof(struct __filenode_hdr));

    return (buffer + sizeof(struct __filenode_hdr));
}

int
filenode_serialize(struct nexus_filenode * filenode, uint8_t * buffer)
{
    struct chunk_entry_s * curr_chunk_entry = NULL;
    struct chunk_entry_s * tmp_chunk_entry  = NULL;

    uint8_t * output_ptr = NULL;


    output_ptr = __serialize_filenode_header(filenode, buffer);

    if (output_ptr == NULL) {
        log_error("could not parse filenode header\n");
        return -1;
    }

    tmp_chunk_entry = (struct chunk_entry_s *) output_ptr;

    for (size_t i = 0; i < filenode->nchunks; i++) {
        curr_chunk_entry = nexus_list_get(&filenode->chunk_list, i);

        memcpy(tmp_chunk_entry, curr_chunk_entry, sizeof(struct chunk_entry_s));

        tmp_chunk_entry++;
    }

    return 0;
}

int
filenode_store(struct nexus_filenode * filenode, struct nexus_mac * mac)
{
    struct nexus_crypto_buf * crypto_buffer = NULL;

    size_t    serialized_buflen = 0;

    int ret = -1;


    serialized_buflen = __get_filenode_size(filenode);

    crypto_buffer = nexus_crypto_buf_new(serialized_buflen, &filenode->my_uuid);
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

        ret = filenode_serialize(filenode, output_buffer);
        if (ret != 0) {
            log_error("filenode_serialize() FAILED\n");
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

    ret = 0;
out:
    if (crypto_buffer) {
        nexus_crypto_buf_free(crypto_buffer);
    }

    return ret;
}

void
filenode_free(struct nexus_filenode * filenode)
{
    nexus_list_destroy(&filenode->chunk_list);
    nexus_free(filenode);
}

// XXX this could be optimized for larger allocations
int
filenode_set_filesize(struct nexus_filenode * filenode, size_t filesize)
{
    size_t nchunks = get_chunk_count(filenode, filesize);

    int difference = nchunks - filenode->nchunks;

    if (difference == 0) {
        filenode->filesize = filesize;
        return 0;
    }

    filenode->nchunks  = nchunks;
    filenode->filesize = filesize;

    // if the file got smaller, we need to pop off some entries
    while (difference < 0) {
        struct chunk_entry_s * chunk_entry = nexus_list_pop(&filenode->chunk_list);

        __free_chunk_entry(chunk_entry);

        difference++;
    }

    while (difference > 0) {
        struct chunk_entry_s * chunk_entry = nexus_malloc(sizeof(struct chunk_entry_s));

        nexus_list_append(&filenode->chunk_list, chunk_entry);

        difference--;
    }

    return 0;
}

struct nexus_crypto_ctx *
filenode_get_chunk(struct nexus_filenode * filenode, size_t offset)
{
    size_t chunk_num = get_chunk_number(filenode, offset);

    struct chunk_entry_s * chunk_entry = nexus_list_get(&filenode->chunk_list, chunk_num);

    return chunk_entry ? &chunk_entry->crypto_ctx : NULL;
}
