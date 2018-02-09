#include "enclave_internal.h"

struct __filenode_hdr {
    uint32_t nchunks;
    uint8_t  log2chunksize;
    uint64_t filesize;
} __attribute__((packed));

struct chunk_entry_s {
    struct nexus_crypto_ctx crypto_ctx;
} __attribute__((packed));



static inline size_t
get_chunk_number(struct nexus_filebox * filebox, size_t offset)
{
    return ((offset < filebox->chunksize)
                ? 0
                : 1 + ((offset - (size_t)filebox->chunksize) >> filebox->log2chunksize));
}

static inline size_t
get_chunk_count(size_t file_size)
{
    return get_chunk_number(file_size) + 1;
}



static void
__free_chunk_entry(void * element)
{
    free(element);
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
filenode_create(struct nexus_uuid * root_uuid, size_t log2chunksize)
{
    struct nexus_filenode * filenode = NULL;

    filenode = nexus_malloc(sizeof(struct nexus_filenode));

    nexus_uuid_gen(&filenode->my_uuid);
    nexus_uuid_copy(root_uuid, &filenode->root_uuid);

    filenode_init(filenode, log2chunksize);

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

    filenode_init(filenode, header->log2chunksize);

    return (buffer + sizeof(struct __filenode_hdr));
}

struct nexus_filenode *
filenode_from_buffer(uint8_t * buffer, size_t buflen)
{
    struct nexus_filenode * filenode = NULL;

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
        struct chunk_entry_s * new_chunk_entry = nexus_malloc(sizeof(struct chunk_entry_s));

        memcpy(new_chunk_entry, tmp_chunk_entry, sizeof(struct chunk_entry_s));

        nexus_list_append(&filenode->chunk_list, new_chunk_entry);

        tmp_chunk_entry++;
    }

    return filenode;
}

static uint8_t *
__serialize_filenode_header(struct nexus_filenode * filenode, uint8_t * buffer)
{
    struct __filenode_hdr * header = NULL;

    if (buflen < sizeof(struct __filenode_hdr)) {
        log_error("buffer is too small to fit a filenode\n");
        return NULL;
    }


    header = (struct __filenode_hdr *)buffer;

    header->nchunks       = filenode->nchunks;
    header->log2chunksize = filenode->log2chunksize;
    header->filesize      = filenode->filesize;

    memcpy(buffer, header, sizeof(struct __filenode_hdr));

    return (buffer + sizeof(struct __filenode_hdr));
}

struct nexus_filenode *
filenode_to_buffer(uint8_t * buffer, size_t buflen)
{
    struct nexus_filenode * filenode = NULL;

    struct chunk_entry_s * tmp_chunk_entry = NULL;

    uint8_t * output_ptr = NULL;


    filenode = nexus_malloc(sizeof(struct nexus_filenode));

    output_ptr = __serialize_filenode_header(filenode, buffer, buflen);

    if (output_ptr == NULL) {
        nexus_free(filenode);
        log_error("could not parse filenode header\n");
        return NULL;
    }

    tmp_chunk_entry = (struct chunk_entry_s *) output_ptr;

    for (size_t i = 0; i < filenode->nchunks; i++) {
        struct chunk_entry_s * curr_chunk_entry = nexus_list_get(i);

        memcpy(tmp_chunk_entry, new_chunk_entry, sizeof(struct chunk_entry_s));

        tmp_chunk_entry++;
    }

    return filenode;
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
        return 0;
    }

    filenode->nchunks = nchunks;

    // if the file got smaller, we need to pop off some entries
    while (difference < 0) {
        struct chunk_entry_s * chunk_entry = nexus_list_pop(&filnode->chunk_list);

        __free_chunk_entry(chunk_entry);

        difference++;
    }

    while (difference > 0) {
        struct chunk_entry_s * chunk_entry = nexus_malloc(sizeof(struct chunk_entry_s));

        nexus_list_append(&filnode->chunk_list, chunk_entry);

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
