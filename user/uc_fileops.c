#include <stdlib.h>

#include "third/seqptrmap.h"
#include "third/slog.h"

#include "uc_dcache.h"
#include "uc_filebox.h"
#include "uc_sgx.h"
#include "uc_types.h"
#include "uc_uspace.h"

struct seqptrmap * xfer_context_array = NULL;

static void
free_xfer_context(xfer_context_t * xfer_ctx)
{
    if (xfer_ctx->path) {
        sdsfree(xfer_ctx->path);
    }

    if (xfer_ctx->buffer) {
        free(xfer_ctx->buffer);
    }

    free(xfer_ctx);
}

xfer_context_t *
fileops_start(int op,
              const char * fpath,
              uint32_t max_xfer_size,
              uint32_t filelength,
              int * retptr)
{
    int ret = -1;
    size_t id = 0;
    crypto_context_t * crypto_ctx = NULL;
    uc_filebox_t * fb = NULL;
    xfer_context_t * xfer_ctx = NULL;

    *retptr = -2;

    /* get the filebox object */
    if ((fb = dcache_get_filebox(fpath)) == NULL) {
        *retptr = -1;
        slog(0, SLOG_ERROR, "fileops - filebox (%s) could not be found", fpath);
        return NULL;
    }

    /* TODO: change the argument to the appropriate index */
    crypto_ctx = filebox_get_crypto(fb, 0);

    xfer_ctx = (xfer_context_t *)calloc(1, sizeof(xfer_context_t));
    if (xfer_ctx == NULL) {
        slog(0, SLOG_FATAL, "fileops - memory allocation failed");
        return NULL;
    }

    // XXX check the size of max_xfer_size
    xfer_ctx->buffer = (char *)malloc(max_xfer_size);
    if (xfer_ctx->buffer == NULL) {
        free(xfer_ctx);
        return NULL;
    }

    xfer_ctx->op = op;
    xfer_ctx->completed = 0;
    xfer_ctx->buflen = max_xfer_size;
    xfer_ctx->raw_len = filelength;
    xfer_ctx->path = sdsnew(fpath);

    ecall_init_crypto(global_eid, &ret, xfer_ctx, crypto_ctx);
    if (ret) {
        slog(0, SLOG_FATAL, "fileops - Enclave error on starting operation");
        free_xfer_context(xfer_ctx);
        return NULL;
    }

    if ((xfer_ctx->id = seqptrmap_add(xfer_context_array, xfer_ctx)) == -1) {
        // TODO delete context from enclave space
        slog(0, SLOG_ERROR, "fileops - Adding to list failed");
        free_xfer_context(xfer_ctx);
        return NULL;
    }

    return xfer_ctx;
}

xfer_context_t *
fileops_get_context(size_t id)
{
    return seqptrmap_get(xfer_context_array, id);
}

int
fileops_process_data(xfer_context_t * ctx)
{
    int ret = 0;

    // hexdump((uint8_t *)ctx->buffer, ctx->valid_buflen > 50 ? 50 :
    // ctx->valid_buflen);
    // ecall_crypt_data(global_eid, &ret, ctx);
    if (ret) {
        goto out;
    }
    // hexdump((uint8_t *)ctx->buffer, ctx->valid_buflen > 50 ? 50 :
    // ctx->valid_buflen);

    ctx->completed += ctx->valid_buflen;
out:
    return ret;
}

int
fileops_finish(size_t id)
{
    uc_filebox_t * fb;
    xfer_context_t * xfer_ctx;
    crypto_context_t * crypto_ctx;
    int ret = -2;

    xfer_ctx = seqptrmap_get(xfer_context_array, id);
    if (xfer_ctx == NULL) {
        return ret;
    }

    if ((fb = filebox_from_file(xfer_ctx->path)) == NULL) {
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
    }

    seqptrmap_delete(xfer_context_array, id);
    free_xfer_context(xfer_ctx);

    return ret;
}
