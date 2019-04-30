#include "enclave_internal.h"

// TODO
// - add init/deinit() to create/destroy hashmap


// this structure describes a single transfer context that handles the encryption
// of file data. The offset is automatically updated on every updated, and whenever
// we reach the end of the chunk; the user has to explicitly seek to continue
// encrypting.
struct data_xfer_context {
    struct hashmap_entry    entry;

    nexus_crypto_mode_t     mode;


    size_t                  id;

    size_t                  offset;

    size_t                  chunk_left; // the amount of chunk left to encrypt


    struct nexus_filenode * filenode;

    struct nexus_metadata * metadata;


    struct nexus_crypto_ctx * crypto_context;


    struct nexus_data_buf * data_buffer; // the current data buffer
};




static struct hashmap     *  xfer_table = NULL;

static size_t                xfer_counter = 0;


int
_isequals_function(const void                     * hashmap_cmp_fn_data,
                   const struct data_xfer_context * xfer_ctx1,
                   const struct data_xfer_context * xfer_ctx2,
                   const void                     * keydata)
{
    if (xfer_ctx1->id == xfer_ctx2->id) {
        return 0;
    }

    return -1;
}


int
__put_context(struct data_xfer_context * xfer_context)
{
    if (xfer_table == NULL) {
        xfer_table = nexus_malloc(sizeof(struct hashmap));

        hashmap_init(xfer_table, (hashmap_cmp_fn)_isequals_function, NULL, 16);
    }

    xfer_counter += 1;

    xfer_context->id = xfer_counter;

    hashmap_entry_init(&xfer_context->entry, xfer_context->id);

    hashmap_add(xfer_table, &xfer_context->entry);

    return 0;
}

struct data_xfer_context *
__get_context(int context_id)
{
    struct data_xfer_context tmp_context;

    hashmap_entry_init(&tmp_context.entry, context_id);
    tmp_context.id = context_id;

    return hashmap_get(xfer_table, &tmp_context, NULL);
}

void
__del_context(struct data_xfer_context * xfer_context)
{
    __hashmap_remove_entry(xfer_table, &xfer_context->entry);
    nexus_free(xfer_context);
}



int
file_crypto_new(struct nexus_metadata * metadata, nexus_crypto_mode_t mode)
{
    struct data_xfer_context * xfer_context = nexus_malloc(sizeof(struct data_xfer_context));

    xfer_context->metadata = metadata;
    xfer_context->filenode = metadata->filenode;
    xfer_context->mode     = mode;

    if (__put_context(xfer_context)) {
        log_error("could not add transfer context\n");
        return -1;
    }

    return xfer_context->id;
}

int
__setup_data_buffer(struct data_xfer_context * xfer_context, size_t offset)
{
    xfer_context->crypto_context = filenode_get_chunk(xfer_context->filenode,
                                                      offset,
                                                      xfer_context->mode == NEXUS_ENCRYPT);

    if (xfer_context->crypto_context == NULL) {
        log_error("filenode_get_chunk(offset=%zu)\n", xfer_context->offset);
        return -1;
    }


    xfer_context->data_buffer = nexus_data_buf_new(xfer_context->crypto_context,
                                                   global_chunk_size,
                                                   xfer_context->mode);

    if (xfer_context->data_buffer == NULL) {
        log_error("could not create a new data_buffer\n");
        return -1;
    }

    xfer_context->offset     = offset;
    xfer_context->chunk_left = min(xfer_context->filenode->filesize - offset, global_chunk_size);

    return 0;
}

int
file_crypto_seek(int xfer_id, size_t offset)
{
    struct data_xfer_context * xfer_context = __get_context(xfer_id);

    if (xfer_context == NULL) {
        log_error("context could not be found\n");
        return -1;
    }

    if (xfer_context->chunk_left) {
        log_error("%zu bytes left in the current chunk\n", xfer_context->chunk_left);
        return -1;
    }

    if (offset % global_chunk_size) {
        log_error("offset (%zu) is not a multiple of chunk size (%zu)\n",
                  offset, global_chunk_size);
        return -1;
    }


    if (offset > xfer_context->filenode->filesize) {
        log_error("offset (%zu) cannot exceed filesize(%zu)\n",
                  offset, xfer_context->filenode->filesize);
        return -1;
    }


    if (__setup_data_buffer(xfer_context, offset)) {
        log_error("__setup_data_buffer() FAILED\n");
        return -1;
    }

    return 0;
}

int
__flush_data_buffer(struct data_xfer_context * xfer_context)
{
    int ret = 0;

    if (xfer_context->mode == NEXUS_ENCRYPT) {
        nexus_data_buf_flush(xfer_context->data_buffer, &xfer_context->crypto_context->mac);

        filenode_update_encrypted_pos(xfer_context->filenode, xfer_context->offset);
    } else if (xfer_context->offset < xfer_context->filenode->encrypted_length) {
        // FIXME: When a file gets truncated, we only shorten the file without re-encrypting its
        // now shortened content (new mac). So, until we change this procedure, we shall just
        // skip verification of last chunks. FIX IT SOON !!!
        //
        // DECRYPT
        struct nexus_mac computed_mac;

        nexus_data_buf_flush(xfer_context->data_buffer, &computed_mac);

        if (nexus_mac_compare(&xfer_context->crypto_context->mac, &computed_mac)) {
            log_error("mac comparison FAILED\n");
            ret = -1;
        }
    }

    nexus_data_buf_free(xfer_context->data_buffer);

    xfer_context->data_buffer    = NULL;

    xfer_context->crypto_context = NULL;

    return ret;
}

int
file_crypto_update(int       xfer_id,
                   uint8_t * input_buffer,
                   uint8_t * output_buffer,
                   size_t    size,
                   size_t  * processed_bytes)
{
    struct data_xfer_context * xfer_context = __get_context(xfer_id);

    size_t nbytes = 0;


    if (xfer_context == NULL) {
        log_error("context could not be found\n");
        return -1;
    }

    if (xfer_context->data_buffer == NULL) {
        log_error("there is no data buffer, seek to offset\n");
        return -2;
    }

    nbytes = min(size, xfer_context->chunk_left);

    if (nexus_data_buf_write(xfer_context->data_buffer, input_buffer, output_buffer, nbytes)) {
        log_error("nexus_data_buf_write() size=%zu, nbytes=%zu FAILED\n", size, nbytes);
        return -1;
    }

    *processed_bytes = nbytes;

    xfer_context->chunk_left -= nbytes;
    xfer_context->offset     += nbytes;

    // if there is no chunk left, let's close this data buffer
    if ((xfer_context->chunk_left == 0) && __flush_data_buffer(xfer_context)) {
        log_error("__flush_data_buffer() FAILED\n");
        return -1;
    }

    return 0;
}


int
file_crypto_finish(int xfer_id)
{
    struct data_xfer_context * xfer_context = __get_context(xfer_id);

    if (xfer_context == NULL) {
        log_error("context could not be found\n");
        return -1;
    }

    if (nexus_metadata_store(xfer_context->metadata)) {
        nexus_vfs_put(xfer_context->metadata);
        __del_context(xfer_context);
        log_error("nexus_metadata_store() on file_crypto FAILED\n");
        return -1;
    }

    nexus_vfs_put(xfer_context->metadata);

    __del_context(xfer_context);

    return 0;
}
