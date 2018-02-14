#include "enclave_internal.h"

// stores information about a particular transfer

struct xfer_context {
    int    xfer_id;

    xfer_op_t mode;

    size_t start_offset;
    size_t curr_offset;

    size_t chunksize;

    struct nexus_filenode   * filenode;

    // the currently used contexts
    struct nexus_crypto_ctx * filenode_crypto_ctx_ptr;
    struct nexus_data_buf   * data_buffer;
};


static struct nexus_list xfer_list;

static size_t xfer_list_size = 0;


static void
free_xfer_context(void * ctx)
{
    struct xfer_context * xfer_ctx = (struct xfer_context *)ctx;

    if (xfer_ctx->data_buffer) {
        nexus_data_buf_free(xfer_ctx->data_buffer);
    }

    nexus_free(xfer_ctx);
}

static struct nexus_list_iterator *
find_xfer_context(int xfer_id)
{
    struct xfer_context * xfer_ctx = NULL;

    struct nexus_list_iterator * iter = NULL;

    if (xfer_id < 0) {
        return NULL;
    }

    iter = list_iterator_new(&xfer_list);

    while (list_iterator_is_valid(iter)) {
        xfer_ctx = list_iterator_get(iter);

        if (xfer_ctx->xfer_id == xfer_id) {
            return iter;
        }

        list_iterator_next(iter);
    }

    list_iterator_free(iter);

    return NULL;
}

void
transfer_layer_init()
{
    nexus_list_init(&xfer_list);
    nexus_list_set_deallocator(&xfer_list, free_xfer_context);

    xfer_list_size = 0;
}

void
transfer_layer_exit()
{
    nexus_list_destroy(&xfer_list);
}

int
transfer_layer_new(size_t offset, struct nexus_filenode * filenode)
{
    struct xfer_context * xfer_ctx = NULL;

    if (offset % filenode->chunksize) {
        log_error("starting offset (val=%zu) must be a multiple of the chunk size (%d)\n",
                  offset, filenode->chunksize);

        return -1;
    }

    xfer_ctx = nexus_malloc(sizeof(struct xfer_context));

    xfer_ctx->xfer_id       = xfer_list_size;
    xfer_ctx->start_offset  = offset;
    xfer_ctx->curr_offset   = offset;
    xfer_ctx->chunksize     = filenode->chunksize;
    xfer_ctx->filenode      = filenode;

    xfer_list_size += 1;

    nexus_list_append(&xfer_list, xfer_ctx);

    return xfer_ctx->xfer_id;
}

static int
generate_data_buffer(struct xfer_context * xfer_ctx)
{
    struct nexus_data_buf * data_buffer = NULL;

    struct nexus_crypto_ctx * crypto_ctx = NULL;


    // get the corresponding context from the filenode
    crypto_ctx = filenode_get_chunk(xfer_ctx->filenode, xfer_ctx->curr_offset);
    if (crypto_ctx == NULL) {
        log_error("filenode could not find\n");
        return -1;
    }

    if (xfer_ctx->mode == XFER_ENCRYPT) {
        nexus_crypto_ctx_generate(crypto_ctx);
    }

    data_buffer = nexus_data_buf_create(NEXUS_CHUNK_SIZE);
    if (data_buffer == NULL) {
        log_error("nexus_data_buf_create FAILED\n");
        return -1;
    }

    nexus_data_buf_start(data_buffer, crypto_ctx, xfer_ctx->mode);

    xfer_ctx->data_buffer             = data_buffer;
    xfer_ctx->filenode_crypto_ctx_ptr = crypto_ctx;

    return 0;
}

static int
prepare_data_buffer(struct xfer_context * xfer_ctx)
{
    // if we are not at a chunk boundary
    if (xfer_ctx->curr_offset % xfer_ctx->chunksize) {
        return 0;
    }

    if (generate_data_buffer(xfer_ctx)) {
        log_error("could not create data buffer\n");
        return -1;
    }

    return 0;
}

static int
postprocess_data_buffer(struct xfer_context * xfer_ctx)
{
    struct nexus_mac   computed_mac;
    struct nexus_mac * stored_mac = NULL;

    // if we are not at a chunk boundary, we can keep using the same data buffer
    if (xfer_ctx->curr_offset % xfer_ctx->chunksize) {
        return 0;
    }

    stored_mac = &(xfer_ctx->filenode_crypto_ctx_ptr->mac);

    if (xfer_ctx->mode == XFER_ENCRYPT) {
        nexus_data_buf_finish(xfer_ctx->data_buffer, stored_mac);
        return 0;
    }

    // XFER_DECRYPT
    nexus_data_buf_finish(xfer_ctx->data_buffer, &computed_mac);

    if (nexus_mac_compare(stored_mac, &computed_mac)) {
        log_error("mac comparison FAILED\n");
        return -1;
    }

    return 0;
}

int
transfer_layer_process(int xfer_id, uint8_t * external_addr, size_t buflen)
{
    struct nexus_list_iterator * iter = NULL;

    struct xfer_context * xfer_ctx = NULL;

    uint8_t * external_ptr = NULL;

    size_t processed  = 0;
    int    bytes_left = 0;

    int ret = -1;


    iter = find_xfer_context(xfer_id);
    if (iter == NULL) {
        log_error("could not find xfer context (xfer_id=%d)\n", xfer_id);
        return -1;
    }

    xfer_ctx = list_iterator_get(iter);
    list_iterator_free(iter);

    external_ptr = external_addr;

    bytes_left = buflen;


next_chunk:
    ret = prepare_data_buffer(xfer_ctx);
    if (ret != 0) {
        log_error("preparing the data buffer FAILED\n");
        return -1;
    }

    ret = nexus_data_buf_update(xfer_ctx->data_buffer, external_ptr, bytes_left, &processed);
    if (ret != 0) {
        log_error("nexus_data_buf_update FAILED()\n");
        return -1;
    }

    external_ptr += processed;
    bytes_left   -= processed;

    xfer_ctx->curr_offset += processed;

    ret = postprocess_data_buffer(xfer_ctx);
    if (ret != 0) {
        log_error("post processing data buffer FAILED\n");
        return -1;
    }

    // if there is more to process...
    if (bytes_left > 0) {
        goto next_chunk;
    }

    return 0;
}

int
transfer_layer_free(int xfer_id)
{
    struct nexus_list_iterator * iter = NULL;

    iter = find_xfer_context(xfer_id);
    if (iter == NULL) {
        return -1;
    }

    list_iterator_del(iter);

    list_iterator_free(iter);

    return 0;
}
