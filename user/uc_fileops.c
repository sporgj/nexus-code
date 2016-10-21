#include <stdlib.h>

#include "third/seqptrmap.h"
#include "third/slog.h"

#include "uc_dcache.h"
#include "uc_filebox.h"
#include "uc_sgx.h"
#include "uc_types.h"
#include "uc_uspace.h"
#include "uc_utils.h"

struct seqptrmap * xfer_context_array = NULL;

static void
free_xfer_context(xfer_context_t * xfer_ctx)
{
    if (xfer_ctx->path) {
        free(xfer_ctx->path);
    }

    if (xfer_ctx->buffer) {
        free(xfer_ctx->buffer);
    }

    free(xfer_ctx);
}

int
fileops_start(int op,
              const char * fpath,
              uint32_t max_xfer_size,
              int32_t position,
              uint32_t total_len,
              int * p_id)
{
    int ret = -1;
    crypto_context_t * crypto_ctx = NULL;
    uc_filebox_t * fb = NULL;
    xfer_context_t * xfer_ctx = NULL;

    *p_id = -2;

    if (position % 16) {
        slog(0, SLOG_ERROR, "fileops - invalid offset(%d)", position);
        return ret;
    }

    if ((op & UC_ENCRYPT) && (op & UC_DECRYPT)) {
        slog(0, SLOG_ERROR, "fileops - Can't try to encrypt and decrypt");
        return ret;
    }

    /* get the filebox object */
    if ((fb = dcache_get_filebox(fpath)) == NULL) {
        slog(0, SLOG_ERROR, "fileops - filebox (%s) could not be found", fpath);
        return ret;
    }

    xfer_ctx = (xfer_context_t *)calloc(1, sizeof(xfer_context_t));
    if (xfer_ctx == NULL) {
        slog(0, SLOG_FATAL, "fileops - memory allocation failed");
        filebox_free(fb);
        return ret;
    }

    // XXX check the size of max_xfer_size
    xfer_ctx->buffer = (char *)malloc(max_xfer_size);
    if (xfer_ctx->buffer == NULL) {
        slog(0, SLOG_FATAL, "fileops - xfer_ctx buffer allocation failed");
        goto out;
    }

    xfer_ctx->op = op;
    xfer_ctx->completed = 0;
    xfer_ctx->buflen = max_xfer_size;
    xfer_ctx->position = position;
    xfer_ctx->total_len = total_len;
    xfer_ctx->path = strdup(fpath);

    /* TODO: change the argument to the appropriate index */
    if ((crypto_ctx = filebox_get_crypto(fb, 0)) == NULL) {
        slog(0, SLOG_ERROR, "fileops - crypto ctx could not be retrieved");
        goto out;
    }

    ecall_init_crypto(global_eid, &ret, xfer_ctx, crypto_ctx);
    if (ret) {
        slog(0, SLOG_FATAL, "fileops - Enclave error on starting operation");
        goto out;
    }

    /* TODO move this to an init function */
    if (xfer_context_array == NULL) {
        xfer_context_array = seqptrmap_init();
    }

    if ((xfer_ctx->xfer_id = seqptrmap_add(xfer_context_array, xfer_ctx)) == -1) {
        // TODO delete context from enclave space
        slog(0, SLOG_ERROR, "fileops - Adding to list failed");
        goto out;
    }

    *p_id = xfer_ctx->xfer_id;
    ret = 0;
out:
    if (crypto_ctx) {
        free(crypto_ctx);
    }

    if (ret && xfer_ctx) {
        free_xfer_context(xfer_ctx);
    }

    filebox_free(fb);
    return ret;
}

uint8_t **
fileops_get_buffer(int id, size_t valid_buflen)
{
    xfer_context_t * xfer_ctx = seqptrmap_get(xfer_context_array, id);
    if (xfer_ctx == NULL) {
        slog(0, SLOG_ERROR, "fileops - id=%d could not be found", id);
        return NULL;
    }

    if (valid_buflen > xfer_ctx->buflen) {
        slog(0, SLOG_ERROR, "fileops - id (%d) valid buflen too big (%d > %d)",
             id, valid_buflen, xfer_ctx->buflen);
        return NULL;
    }

    xfer_ctx->valid_buflen = valid_buflen;
    return (uint8_t **)&xfer_ctx->buffer;
}

int
fileops_process_data(uint8_t ** buffer)
{
    int ret = 0;
    xfer_context_t * xfer_ctx
        = (xfer_context_t *)((uintptr_t)buffer
                             - offsetof(xfer_context_t, buffer));

    //hexdump(*buffer, MIN(xfer_ctx->valid_buflen, 32));
    ecall_crypt_data(global_eid, &ret, xfer_ctx);
    if (ret) {
        goto out;
    }
    //hexdump(*buffer, MIN(xfer_ctx->valid_buflen, 32));

    xfer_ctx->completed += xfer_ctx->valid_buflen;
out:
    return ret;
}

int
fileops_finish(int id)
{
    uc_filebox_t * fb;
    xfer_context_t * xfer_ctx;
    crypto_context_t * crypto_ctx;
    int ret = -2;

    xfer_ctx = seqptrmap_get(xfer_context_array, id);
    if (xfer_ctx == NULL) {
        return ret;
    }

    if ((fb = dcache_get_filebox(xfer_ctx->path)) == NULL) {
        slog(0, SLOG_ERROR, "fileops - filebox(%s) failed", xfer_ctx->path);
        return ret;
    }

    if ((crypto_ctx = filebox_get_crypto(fb, 0)) == NULL) {
        slog(0, SLOG_ERROR, "fileops - filebox operation failed");
        return ret;
    }

    /* now we can proceed with the crypto stuff */
    ecall_finish_crypto(global_eid, &ret, xfer_ctx, crypto_ctx);
    if (ret) {
        slog(0, SLOG_ERROR, "fileops - Crypto operation failed");
        goto out;
    }

    /* save the filebox to disk */
    if (xfer_ctx->op == UC_ENCRYPT) {
        filebox_set_crypto(fb, 0, crypto_ctx);
        filebox_flush(fb);
        filebox_free(fb);
    }

    ret = 0;
out:
    seqptrmap_delete(xfer_context_array, id);
    free_xfer_context(xfer_ctx);

    return ret;
}
